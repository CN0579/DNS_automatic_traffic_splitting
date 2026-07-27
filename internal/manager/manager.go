package manager

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"
	_ "time/tzdata"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/querylog"
	"doh-autoproxy/internal/router"
	"doh-autoproxy/internal/server"
	"doh-autoproxy/internal/util"
)

type ServiceManager struct {
	mu     sync.Mutex
	Config *config.Config

	stopOnce sync.Once

	GeoManager  *router.GeoDataManager
	Router      *router.Router
	CertManager *util.CertManager
	QueryLog    *querylog.QueryLogger

	DNSServer  *server.DNSServer
	DoTServer  *server.DoTServer
	DoHServer  *server.DoHServer
	DoQServer  *server.DoQServer
	ACMEServer *http.Server

	stopAutoUpdate chan struct{}
}

func NewServiceManager(initialCfg *config.Config) *ServiceManager {
	return &ServiceManager{
		Config:         initialCfg,
		stopAutoUpdate: make(chan struct{}),
	}
}

func (m *ServiceManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.startInternal(); err != nil {
		return err
	}
	go m.runAutoUpdate()
	return nil
}

func (m *ServiceManager) Stop() error {
	// 关闭而非发送：非阻塞发送在 runAutoUpdate 未停在 select 上时会被
	// default 分支丢弃，导致停止信号丢失、goroutine 泄漏，
	// 并可能在服务停止后重新拉起所有监听器。
	m.stopOnce.Do(func() {
		close(m.stopAutoUpdate)
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stopInternal()
}

// Snapshot 在持有锁的情况下返回当前的运行时组件，供 Web 处理器等外部调用方使用。
// 直接读取字段会与 Reload() 中的置空/替换产生数据竞争和 nil 解引用 panic。
func (m *ServiceManager) Snapshot() (*config.Config, *router.Router, *querylog.QueryLogger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Config, m.Router, m.QueryLog
}

// CurrentConfig 在持有锁的情况下返回当前配置。
func (m *ServiceManager) CurrentConfig() *config.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Config
}

// stopped 报告是否已请求停止。
func (m *ServiceManager) stopped() bool {
	select {
	case <-m.stopAutoUpdate:
		return true
	default:
		return false
	}
}

func (m *ServiceManager) Reload(newCfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("正在重新加载服务配置...")

	geoChanged := m.Config.GeoData.GeoIPDat != newCfg.GeoData.GeoIPDat ||
		m.Config.GeoData.GeoSiteDat != newCfg.GeoData.GeoSiteDat

	if geoChanged {
		log.Println("GeoData 配置已更改，将在重新启动期间重新加载 Geo 数据库。")
		m.GeoManager = nil
		debug.FreeOSMemory()
	} else {
		log.Println("GeoData 配置未更改，保留现有的 Geo 数据库以加快重新加载。")
	}

	if err := m.stopInternal(); err != nil {
		log.Printf("Warning: Error stopping services during reload: %v", err)
	}

	if m.Config.QueryLog.SaveToFile && !newCfg.QueryLog.SaveToFile {
		logFile := m.Config.QueryLog.File
		if logFile == "" {
			logFile = "query.log"
		}
		log.Printf("持久化存储已关闭，正在删除日志文件: %s", logFile)
		if err := os.Remove(logFile); err != nil && !os.IsNotExist(err) {
			log.Printf("删除日志文件失败: %v", err)
		}
	}

	oldCfg := m.Config
	m.Config = newCfg

	if err := m.startInternal(); err != nil {
		// 新配置启动失败时回滚到旧配置，否则所有监听器都已停止，
		// 服务将彻底不可用，只能靠人工重启恢复。
		log.Printf("新配置启动失败，正在回滚: %v", err)
		m.Config = oldCfg
		m.GeoManager = nil
		if stopErr := m.stopInternal(); stopErr != nil {
			log.Printf("Warning: 回滚前停止服务出错: %v", stopErr)
		}
		if rollbackErr := m.startInternal(); rollbackErr != nil {
			return fmt.Errorf("failed to restart services: %w (回滚同样失败: %v)", err, rollbackErr)
		}
		log.Println("已回滚到上一份可用配置")
		return fmt.Errorf("failed to restart services: %w", err)
	}

	log.Println("服务配置重载完成")
	return nil
}

// reloadCurrent 使用当前配置就地重启服务，并强制重新加载 Geo 数据库。
// 与 Reload 不同，它不会替换 m.Config，因此不会覆盖并发保存的新配置。
func (m *ServiceManager) reloadCurrent() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GeoManager = nil
	debug.FreeOSMemory()

	if err := m.stopInternal(); err != nil {
		log.Printf("Warning: Error stopping services during geo reload: %v", err)
	}

	if err := m.startInternal(); err != nil {
		return fmt.Errorf("failed to restart services: %w", err)
	}
	return nil
}

func (m *ServiceManager) CheckAndDownloadGeoFiles() {
	shouldDownload := func(path string) bool {
		fi, err := os.Stat(path)
		if err != nil {
			return os.IsNotExist(err)
		}
		return fi.Size() == 0
	}

	cfg := m.CurrentConfig()

	if shouldDownload(cfg.GeoData.GeoIPDat) {
		if cfg.GeoData.GeoIPDownloadURL != "" {
			log.Printf("GeoIP 文件 %s 不存在或为空，正在从 %s 下载...", cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL)
			if err := util.DownloadFile(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL, router.VerifyGeoIP); err != nil {
				log.Printf("错误: 下载 GeoIP 文件失败: %v", err)
			} else {
				log.Println("GeoIP 文件下载成功")
			}
		}
	}

	if shouldDownload(cfg.GeoData.GeoSiteDat) {
		if cfg.GeoData.GeoSiteDownloadURL != "" {
			log.Printf("GeoSite 文件 %s 不存在或为空，正在从 %s 下载...", cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL)
			if err := util.DownloadFile(cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL, router.VerifyGeoSite); err != nil {
				log.Printf("错误: 下载 GeoSite 文件失败: %v", err)
			} else {
				log.Println("GeoSite 文件下载成功")
			}
		}
	}
}

func (m *ServiceManager) ForceDownloadGeoFiles() {
	m.downloadGeoFiles(m.CurrentConfig())
}

func (m *ServiceManager) downloadGeoFiles(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if cfg.GeoData.GeoIPDownloadURL != "" {
		log.Printf("正在自动更新 GeoIP 数据...")
		if err := util.DownloadFile(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL, router.VerifyGeoIP); err != nil {
			log.Printf("更新 GeoIP 失败: %v", err)
		}
	}
	if cfg.GeoData.GeoSiteDownloadURL != "" {
		log.Printf("正在自动更新 GeoSite 数据...")
		if err := util.DownloadFile(cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL, router.VerifyGeoSite); err != nil {
			log.Printf("更新 GeoSite 失败: %v", err)
		}
	}
}

func (m *ServiceManager) runAutoUpdate() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	lastAttempt := time.Time{}

	for {
		select {
		case <-m.stopAutoUpdate:
			return
		case <-ticker.C:
			m.mu.Lock()
			cfg := m.Config
			autoUpdate := cfg.GeoData.AutoUpdate
			geoIPFile := cfg.GeoData.GeoIPDat
			m.mu.Unlock()

			if autoUpdate == "" {
				continue
			}

			now := time.Now()
			if loc, err := time.LoadLocation("Asia/Shanghai"); err == nil {
				now = now.In(loc)
			} else {
				log.Printf("无法加载时区 Asia/Shanghai，回退到本地时区: %v", err)
			}

			parsed, err := time.Parse("15:04", autoUpdate)
			if err != nil {
				continue
			}

			targetTime := time.Date(now.Year(), now.Month(), now.Day(), parsed.Hour(), parsed.Minute(), 0, 0, now.Location())

			shouldUpdate := false

			if now.After(targetTime) || now.Equal(targetTime) {
				fi, err := os.Stat(geoIPFile)
				if err != nil {
					shouldUpdate = true
				} else {
					modTime := fi.ModTime().In(now.Location())
					if modTime.Before(targetTime) {
						shouldUpdate = true
					}
				}
			}

			if shouldUpdate {
				if time.Since(lastAttempt) < 1*time.Hour {
					continue
				}

				log.Println("触发计划的 Geo 数据更新 (检测到数据过时)...")
				lastAttempt = time.Now()

				// 下载可能耗时数分钟，期间可能收到停止信号。
				m.downloadGeoFiles(cfg)
				if m.stopped() {
					return
				}

				// 使用当前配置就地重启，避免把可能已过期的 cfg 指针
				// 写回 m.Config 而覆盖掉期间保存的新配置。
				if err := m.reloadCurrent(); err != nil {
					log.Printf("Geo 更新后重载失败: %v", err)
				}
			}
		}
	}
}

func (m *ServiceManager) startInternal() error {
	cfg := m.Config

	if m.GeoManager == nil {
		geoManager, err := router.NewGeoDataManager(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoSiteDat)
		if err != nil {
			return fmt.Errorf("GeoManager init failed: %w", err)
		}
		m.GeoManager = geoManager
	}

	logFile := cfg.QueryLog.File
	if cfg.QueryLog.SaveToFile && logFile == "" {
		logFile = "query.log"
	}
	if m.QueryLog != nil {
		if err := m.QueryLog.Close(); err != nil {
			log.Printf("关闭旧查询日志器失败: %v", err)
		}
	}
	m.QueryLog = querylog.NewQueryLogger(cfg.QueryLog.Enabled, cfg.QueryLog.MaxHistory, cfg.QueryLog.MaxSizeMB, logFile, cfg.QueryLog.SaveToFile)

	m.Router = router.NewRouter(cfg, m.GeoManager, m.QueryLog)

	cm, err := util.NewCertManager(cfg)
	if err != nil {
		log.Printf("无法初始化自动证书管理器: %v (将回退到本地证书)", err)
		m.CertManager = nil
	} else {
		m.CertManager = cm
	}

	if cfg.AutoCert.Enabled && m.CertManager != nil {
		m.ACMEServer = &http.Server{
			Addr: ":80",
			Handler: m.CertManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})),
		}
		go func() {
			log.Println("Starting HTTP server on :80 for ACME challenges")
			if err := m.ACMEServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("ACME HTTP server failed: %v", err)
			}
		}()
	}

	if cfg.Listen.DNSUDP != "" || cfg.Listen.DNSTCP != "" {
		m.DNSServer = server.NewDNSServer(cfg, m.Router)
		m.DNSServer.Start()
	}

	if cfg.Listen.DOT != "" {
		m.DoTServer = server.NewDoTServer(cfg, m.Router, m.CertManager)
		if m.DoTServer != nil {
			m.DoTServer.Start()
		}
	}

	if cfg.Listen.DOQ != "" {
		m.DoQServer = server.NewDoQServer(cfg, m.Router, m.CertManager)
		if m.DoQServer != nil {
			m.DoQServer.Start()
		}
	}

	if cfg.Listen.DOH != "" {
		m.DoHServer = server.NewDoHServer(cfg, m.Router, m.CertManager)
		if m.DoHServer != nil {
			m.DoHServer.Start()
		}
	}

	return nil
}

func (m *ServiceManager) stopInternal() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var firstErr error

	if m.ACMEServer != nil {
		if err := m.ACMEServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		m.ACMEServer = nil
	}

	if m.DNSServer != nil {
		if err := m.DNSServer.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.DNSServer = nil
	}

	if m.DoTServer != nil {
		if err := m.DoTServer.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.DoTServer = nil
	}

	if m.DoQServer != nil {
		if err := m.DoQServer.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.DoQServer = nil
	}

	if m.DoHServer != nil {
		if err := m.DoHServer.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.DoHServer = nil
	}

	if m.Router != nil {
		if err := m.Router.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.Router = nil
	}

	if m.QueryLog != nil {
		if err := m.QueryLog.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.QueryLog = nil
	}

	return firstErr
}

func (m *ServiceManager) GetCertManager() *util.CertManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.CertManager
}
