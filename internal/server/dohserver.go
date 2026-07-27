package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/router"
	"doh-autoproxy/internal/util"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// maxDNSMessageSize 是 DNS over TCP/HTTP 消息的最大长度 (RFC 1035 2 字节长度前缀)。
const maxDNSMessageSize = 65535

type DoHServer struct {
	http2Server *http.Server
	http3Server *http3.Server
	router      *router.Router
	cfg         *config.Config
	wg          sync.WaitGroup
}

func NewDoHServer(cfg *config.Config, r *router.Router, cm *util.CertManager) *DoHServer {
	dohPath := cfg.Listen.DoHPath
	if dohPath == "" {
		dohPath = "/dns-query"
	}

	dohHandler := &DoHRequestHandler{
		router: r,
		path:   dohPath,
	}

	var tlsConfig *tls.Config

	if cm != nil && cm.GetCertificateFunc() != nil {
		log.Println("DoH: Using AutoCert for TLS")
		tlsConfig = &tls.Config{
			GetCertificate: cm.GetCertificateFunc(),
			NextProtos:     []string{"h3", "h2", "http/1.1"},
		}
	} else {
		var certs []tls.Certificate
		var err error

		if len(cfg.TLSCertificates) > 0 {
			certs, err = util.LoadServerCertificates(cfg.TLSCertificates)
			if err != nil {
				log.Printf("Warning: DoH 服务器无法加载配置的证书: %v", err)
				return nil
			}
		} else {
			certs, err = util.LoadServerCertificate("server.crt", "server.key")
			if err != nil {
				log.Printf("Warning: DoH 服务器无法加载默认证书: %v", err)
				return nil
			}
		}

		tlsConfig = &tls.Config{
			Certificates: certs,
			NextProtos:   []string{"h3", "h2", "http/1.1"},
		}
	}

	http2Server := &http.Server{
		Addr:         cfg.Listen.DOHAddr(),
		Handler:      dohHandler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	http3Server := &http3.Server{
		Addr:      cfg.Listen.DOHAddr(),
		TLSConfig: tlsConfig,
		Handler:   dohHandler,
		QUICConfig: &quic.Config{
			MaxIdleTimeout: 30 * time.Second,
		},
	}

	return &DoHServer{
		http2Server: http2Server,
		http3Server: http3Server,
		router:      r,
		cfg:         cfg,
	}
}

func (s *DoHServer) Start() {
	if s.http2Server == nil || s.http3Server == nil {
		log.Println("DoH 服务器未完全初始化，可能因为证书加载失败。")
		return
	}

	// 这些 goroutine 中不能使用 log.Fatalf：重载期间的端口重绑定竞争
	// 会返回 EADDRINUSE，进而 os.Exit 杀死整个 DNS 代理进程。
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("Starting DoH (HTTP/1.1, HTTP/2) server on %s%s", s.http2Server.Addr, s.cfg.Listen.DoHPath)
		err := s.http2Server.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			log.Printf("无法启动DoH (HTTP/1.1, HTTP/2) 服务器: %v", err)
		}
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("Starting DoH (HTTP/3) server on %s%s", s.http3Server.Addr, s.cfg.Listen.DoHPath)

		udpAddr, err := net.ResolveUDPAddr("udp", s.http3Server.Addr)
		if err != nil {
			log.Printf("无法解析HTTP/3监听地址: %v", err)
			return
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			log.Printf("无法监听UDP端口用于HTTP/3: %v", err)
			return
		}
		// 必须在 Serve 返回后关闭，Stop() 会等待本 goroutine 结束，
		// 以保证端口在 startInternal 重新绑定前确实已释放。
		defer udpConn.Close()

		err = s.http3Server.Serve(udpConn)
		if err != nil && err != http.ErrServerClosed && !errors.Is(err, quic.ErrServerClosed) {
			log.Printf("无法启动DoH (HTTP/3) 服务器: %v", err)
		}
	}()
}

func (s *DoHServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.http2Server != nil {
		if err := s.http2Server.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down DoH HTTP/2 server: %v", err)
		}
	}
	if s.http3Server != nil {
		if err := s.http3Server.Close(); err != nil {
			log.Printf("Error closing DoH HTTP/3 server: %v", err)
		}
	}

	// 等待监听 goroutine 退出，确保 UDP/TCP 端口在调用方重新绑定前已释放。
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		log.Printf("Warning: DoH 服务器 goroutine 未在超时前退出")
	}

	return nil
}

type DoHRequestHandler struct {
	router *router.Router
	path   string
}

// isTrustedProxy 判断直连对端是否为可信的本地/私有网络反向代理。
func isTrustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func (h *DoHRequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != h.path {
		http.NotFound(w, r)
		return
	}

	var dnsMsg []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "缺少dns查询参数", http.StatusBadRequest)
			return
		}
		dnsMsg, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "无法解码dns查询参数", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		// 按 media type 比较，忽略可选参数（如 "; charset=utf-8"）。
		mediaType := r.Header.Get("Content-Type")
		if mt, _, err := mime.ParseMediaType(mediaType); err == nil {
			mediaType = mt
		}
		if !strings.EqualFold(mediaType, "application/dns-message") {
			http.Error(w, "Content-Type必须是application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		// 限制请求体大小：DNS over TCP 消息最大 65535 字节，
		// 不设上限会让单个请求耗尽内存。
		dnsMsg, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxDNSMessageSize))
		if err != nil {
			http.Error(w, "无法读取请求体", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "不支持的HTTP方法", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(dnsMsg); err != nil {
		http.Error(w, fmt.Sprintf("无法解包DNS消息: %v", err), http.StatusBadRequest)
		return
	}

	if len(req.Question) == 0 {
		http.Error(w, "DNS请求中没有问题", http.StatusBadRequest)
		return
	}

	qName := strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	// 仅当直连对端本身是可信的（回环/私有网段）反向代理时才采信 XFF；
	// 否则任意公网客户端都能伪造日志中的来源 IP。
	if isTrustedProxy(clientIP) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				clientIP = first
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, err := h.router.Route(ctx, req, clientIP)
	if err != nil {
		log.Printf("Error routing DoH query for %s: %v", qName, err)
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}

	packedResp, err := resp.Pack()
	if err != nil {
		http.Error(w, fmt.Sprintf("无法打包DNS响应: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	// 显式声明长度，便于客户端复用连接；缺省时 Go 会对大响应改用分块传输。
	w.Header().Set("Content-Length", strconv.Itoa(len(packedResp)))
	if _, err := w.Write(packedResp); err != nil {
		log.Printf("Error writing DoH response for %s: %v", qName, err)
	}
}
