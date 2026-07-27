package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"doh-autoproxy/internal/client"
	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/manager"
	"doh-autoproxy/internal/resolver"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

//go:embed ui
var uiFS embed.FS

var (
	sessions  = make(map[string]time.Time)
	sessionMu sync.Mutex
)

const topStatsLimit = 20

// maxAPIBodySize 限制 API 请求体大小，避免恶意请求耗尽内存。
// 配置中可能包含大量 hosts 条目，故留出较宽裕的额度。
const maxAPIBodySize = 32 << 20

// newSessionToken 生成不可预测的会话令牌。
// 旧实现使用 time.Now().UnixNano()，攻击者可猜测登录时刻从而伪造会话。
func newSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// decodeJSONBody 在限制请求体大小后解码 JSON。
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	return json.NewDecoder(io.LimitReader(http.MaxBytesReader(w, r.Body, maxAPIBodySize), maxAPIBodySize)).Decode(dst)
}

type DashboardStats struct {
	UptimeSeconds    int64            `json:"uptime_seconds"`
	MemoryUsageMB    float64          `json:"memory_usage_mb"`
	NumGoroutines    int              `json:"num_goroutines"`
	QPS              float64          `json:"qps"`
	TotalQueries     int64            `json:"total_queries"`
	TotalCN          int64            `json:"total_cn"`
	TotalOverseas    int64            `json:"total_overseas"`
	ListenDNSUDP     string           `json:"listen_dns_udp"`
	ListenDNSTCP     string           `json:"listen_dns_tcp"`
	ListenDOH        string           `json:"listen_doh"`
	ListenDOT        string           `json:"listen_dot"`
	ListenDOQ        string           `json:"listen_doq"`
	UpstreamCN       int              `json:"upstream_cn_count"`
	UpstreamOverseas int              `json:"upstream_overseas_count"`
	UpstreamStats    []interface{}    `json:"upstream_stats,omitempty"`
	TopClients       map[string]int64 `json:"top_clients"`
	TopDomains       map[string]int64 `json:"top_domains"`
}

type TestResult struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Group    string `json:"group"`
	Status   string `json:"status"`
	Latency  string `json:"latency"`
	Error    string `json:"error,omitempty"`
}

func StartWebServer(mgr *manager.ServiceManager) {
	cfg := mgr.CurrentConfig()

	if !cfg.WebUI.Enabled {
		return
	}

	addr := cfg.WebUI.Address
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()

	checkAuth := func(r *http.Request) bool {
		c := mgr.CurrentConfig()
		if c.WebUI.Username == "" || c.WebUI.Password == "" {
			return true
		}
		cookie, err := r.Cookie("session_token")
		if err != nil {
			return false
		}
		sessionMu.Lock()
		defer sessionMu.Unlock()
		pruneExpiredSessionsLocked(time.Now())
		expiry, ok := sessions[cookie.Value]
		return ok && time.Now().Before(expiry)
	}

	mux.HandleFunc("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		c := mgr.CurrentConfig()
		enabled := c.WebUI.Username != "" && c.WebUI.Password != ""
		authenticated := checkAuth(r)
		guestMode := c.WebUI.GuestMode

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":       enabled,
			"authenticated": authenticated,
			"guest_mode":    guestMode,
		})
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decodeJSONBody(w, r, &creds); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		c := mgr.CurrentConfig()
		// 使用常量时间比较，避免通过响应耗时逐字节推断用户名/密码。
		userOK := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(c.WebUI.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(creds.Password), []byte(c.WebUI.Password)) == 1
		if userOK && passOK {
			token, err := newSessionToken()
			if err != nil {
				http.Error(w, "Failed to create session", http.StatusInternalServerError)
				return
			}
			expiry := time.Now().Add(24 * time.Hour)

			sessionMu.Lock()
			pruneExpiredSessionsLocked(time.Now())
			sessions[token] = expiry
			sessionMu.Unlock()

			http.SetCookie(w, &http.Cookie{
				Name:    "session_token",
				Value:   token,
				Expires: expiry,
				MaxAge:  86400,
				// SameSite=Strict：Lax 仍会在顶层导航时携带 Cookie，
				// 配合本服务的状态变更接口不足以防御 CSRF。
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			})
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("session_token"); err == nil {
			sessionMu.Lock()
			delete(sessions, cookie.Value)
			sessionMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		currentCfg := mgr.CurrentConfig()

		if r.Method == http.MethodGet {
			if !currentCfg.WebUI.GuestMode && !checkAuth(r) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			respCfg := *currentCfg
			respCfg.WebUI.Password = "******"
			respCfg.Hosts = nil

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(respCfg)
			return
		}

		if r.Method == http.MethodPost {
			if !checkAuth(r) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			var newCfg config.Config
			if err := decodeJSONBody(w, r, &newCfg); err != nil {
				http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}

			if newCfg.WebUI.Password == "******" {
				newCfg.WebUI.Password = currentCfg.WebUI.Password
			}

			newCfg.Hosts = make(map[string]string, len(currentCfg.Hosts))
			for k, v := range currentCfg.Hosts {
				newCfg.Hosts[k] = v
			}

			configPath := config.GetDefaultConfigPath()
			if err := newCfg.Save(configPath); err != nil {
				http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
				return
			}

			if err := mgr.Reload(&newCfg); err != nil {
				http.Error(w, "Config saved but reload failed: "+err.Error(), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Config saved and service reloaded."))
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		currentCfg := mgr.CurrentConfig()
		if !checkAuth(r) && (!currentCfg.WebUI.GuestMode || r.Method != http.MethodGet) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet {
			page := 1
			limit := 50
			q := strings.ToLower(r.URL.Query().Get("q"))

			if p := r.URL.Query().Get("page"); p != "" {
				fmt.Sscanf(p, "%d", &page)
			}
			if l := r.URL.Query().Get("limit"); l != "" {
				fmt.Sscanf(l, "%d", &limit)
			}
			if page < 1 {
				page = 1
			}
			if limit < 1 {
				limit = 50
			}

			type HostEntry struct {
				Domain string `json:"domain"`
				IP     string `json:"ip"`
			}

			var allHosts []HostEntry
			for k, v := range currentCfg.Hosts {
				if q == "" || strings.Contains(k, q) || strings.Contains(v, q) {
					allHosts = append(allHosts, HostEntry{Domain: k, IP: v})
				}
			}

			sort.Slice(allHosts, func(i, j int) bool {
				return allHosts[i].Domain < allHosts[j].Domain
			})

			total := len(allHosts)
			// page/limit 来自用户输入，(page-1)*limit 可能溢出为负数，
			// 需在切片前把 start/end 夹到 [0, total]。
			start := (page - 1) * limit
			if start < 0 || start > total {
				start = total
			}
			end := start + limit
			if end < start || end > total {
				end = total
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data":  allHosts[start:end],
				"total": total,
				"page":  page,
				"limit": limit,
			})
			return
		}

		if r.Method == http.MethodPost {
			var payload struct {
				Hosts []struct {
					Domain string `json:"domain"`
					IP     string `json:"ip"`
				} `json:"hosts"`
			}
			if err := decodeJSONBody(w, r, &payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			newCfg := *currentCfg
			newCfg.Hosts = make(map[string]string, len(currentCfg.Hosts)+len(payload.Hosts))
			for k, v := range currentCfg.Hosts {
				newCfg.Hosts[k] = v
			}

			for _, h := range payload.Hosts {
				newCfg.Hosts[strings.ToLower(h.Domain)] = h.IP
			}

			configPath := config.GetDefaultConfigPath()
			if err := newCfg.Save(configPath); err != nil {
				http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if err := mgr.Reload(&newCfg); err != nil {
				http.Error(w, "Failed to reload: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodDelete {
			var payload struct {
				Domains []string `json:"domains"`
			}
			if err := decodeJSONBody(w, r, &payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			newCfg := *currentCfg
			newCfg.Hosts = make(map[string]string, len(currentCfg.Hosts))
			for k, v := range currentCfg.Hosts {
				newCfg.Hosts[k] = v
			}

			for _, d := range payload.Domains {
				delete(newCfg.Hosts, strings.ToLower(d))
			}

			configPath := config.GetDefaultConfigPath()
			if err := newCfg.Save(configPath); err != nil {
				http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if err := mgr.Reload(&newCfg); err != nil {
				http.Error(w, "Failed to reload: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/test-upstreams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !checkAuth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var tempCfg config.Config
		if err := decodeJSONBody(w, r, &tempCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		bootstrapper := resolver.NewBootstrapper(tempCfg.BootstrapDNS)
		var results []TestResult
		var mu sync.Mutex
		var wg sync.WaitGroup

		testServer := func(srv config.UpstreamServer, group, target string) {
			defer wg.Done()

			start := time.Now()
			res := TestResult{Address: srv.Address, Protocol: srv.Protocol, Group: group}

			c, err := client.NewDNSClient(srv, bootstrapper)
			if err != nil {
				res.Status = "Error"
				res.Error = err.Error()
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				return
			}

			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(target), dns.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err = c.Resolve(ctx, req)
			duration := time.Since(start)
			res.Latency = duration.String()

			if err != nil {
				res.Status = "Fail"
				res.Error = err.Error()
			} else {
				res.Status = "OK"
			}

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}

		for _, s := range tempCfg.Upstreams.CN {
			wg.Add(1)
			go testServer(s, "CN", "www.baidu.com")
		}
		for _, s := range tempCfg.Upstreams.Overseas {
			wg.Add(1)
			go testServer(s, "Overseas", "www.google.com")
		}

		wg.Wait()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		currentCfg, _, queryLog := mgr.Snapshot()
		if !currentCfg.WebUI.GuestMode && !checkAuth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		limit := 15
		page := 1

		if p := r.URL.Query().Get("page"); p != "" {
			fmt.Sscanf(p, "%d", &page)
			if page < 1 {
				page = 1
			}
		}

		offset := (page - 1) * limit
		if offset < 0 {
			offset = 0
		}
		query := r.URL.Query().Get("q")
		if query == "" {
			query = r.URL.Query().Get("ip")
		}

		logs, total := queryLog.GetLogs(offset, limit, query)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":  logs,
			"total": total,
			"page":  page,
			"limit": limit,
		})
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 一次性取出配置/路由/日志器的快照：Reload() 会整体替换这三个字段，
		// 逐次读取既有数据竞争，也可能拿到互不一致的组合。
		currentCfg, rt, queryLog := mgr.Snapshot()
		if !currentCfg.WebUI.GuestMode && !checkAuth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		stats := queryLog.GetStats()

		resp := DashboardStats{
			UptimeSeconds:    int64(time.Since(stats.StartTime).Seconds()),
			MemoryUsageMB:    float64(m.Alloc) / 1024 / 1024,
			NumGoroutines:    runtime.NumGoroutine(),
			QPS:              stats.QPS,
			TotalQueries:     stats.TotalQueries,
			TotalCN:          stats.TotalCN,
			TotalOverseas:    stats.TotalOverseas,
			ListenDNSUDP:     currentCfg.Listen.DNSUDPAddr(),
			ListenDNSTCP:     currentCfg.Listen.DNSTCPAddr(),
			ListenDOH:        currentCfg.Listen.DOHAddr(),
			ListenDOT:        currentCfg.Listen.DOTAddr(),
			ListenDOQ:        currentCfg.Listen.DOQAddr(),
			UpstreamCN:       len(currentCfg.Upstreams.CN),
			UpstreamOverseas: len(currentCfg.Upstreams.Overseas),
			TopClients:       limitCountMap(stats.TopClients, topStatsLimit),
			TopDomains:       limitCountMap(stats.TopDomains, topStatsLimit),
		}

		resp.UpstreamStats = rt.GetUpstreamStats()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	uiAssets, err := fs.Sub(uiFS, "ui")
	if err != nil {
		// 不使用 log.Fatalf：WebUI 资源缺失不应终止 DNS 服务本身。
		log.Printf("Warning: Failed to embed UI, WebUI not started: %v", err)
		return
	}
	mux.Handle("/", http.FileServer(http.FS(uiAssets)))

	// 显式设置超时：默认的 http.ListenAndServe 无任何超时，
	// 慢速请求（Slowloris）可耗尽连接。
	newServer := func() *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
	}

	go func() {
		certManager := mgr.GetCertManager()

		if cfg.WebUI.CertFile != "" && cfg.WebUI.KeyFile != "" {
			server := newServer()
			log.Printf("WebUI HTTPS started on https://%s (manual cert)", addr)
			if err := server.ListenAndServeTLS(cfg.WebUI.CertFile, cfg.WebUI.KeyFile); err != nil {
				log.Printf("WebUI HTTPS server failed: %v", err)
			}
			return
		}

		if cfg.AutoCert.Enabled && certManager != nil {
			server := newServer()
			server.TLSConfig = certManager.TLSConfig()
			log.Printf("WebUI HTTPS started on https://%s (auto cert)", addr)
			if err := server.ListenAndServeTLS("", ""); err != nil {
				log.Printf("WebUI HTTPS server failed: %v", err)
			}
			return
		}

		server := newServer()
		log.Printf("WebUI HTTP started on http://%s", addr)
		if err := server.ListenAndServe(); err != nil {
			log.Printf("WebUI HTTP server failed: %v", err)
		}
	}()
}

func pruneExpiredSessionsLocked(now time.Time) {
	for token, expiry := range sessions {
		if now.After(expiry) {
			delete(sessions, token)
		}
	}
}

func limitCountMap(source map[string]int64, limit int) map[string]int64 {
	if len(source) == 0 || limit <= 0 || len(source) <= limit {
		result := make(map[string]int64, len(source))
		for key, value := range source {
			result[key] = value
		}
		return result
	}

	type kv struct {
		key   string
		value int64
	}

	items := make([]kv, 0, len(source))
	for key, value := range source {
		items = append(items, kv{key: key, value: value})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].value == items[j].value {
			return items[i].key < items[j].key
		}
		return items[i].value > items[j].value
	})

	result := make(map[string]int64, limit)
	for _, item := range items[:limit] {
		result[item.key] = item.value
	}
	return result
}
