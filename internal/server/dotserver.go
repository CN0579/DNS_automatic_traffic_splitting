package server

import (
	"crypto/tls"
	"log"
	"time"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/router"
	"doh-autoproxy/internal/util"

	"github.com/miekg/dns"
)

type DoTServer struct {
	server *dns.Server
	router *router.Router
	cfg    *config.Config
}

func NewDoTServer(cfg *config.Config, r *router.Router, cm *util.CertManager) *DoTServer {
	handler := &DNSRequestHandler{router: r}

	var tlsConfig *tls.Config

	if cm != nil && cm.GetCertificateFunc() != nil {
		log.Println("DoT: Using AutoCert for TLS")
		tlsConfig = &tls.Config{
			GetCertificate: cm.GetCertificateFunc(),
			NextProtos:     []string{"dns", "h2", "http/1.1"},
		}
	} else {
		var certs []tls.Certificate
		var err error

		if len(cfg.TLSCertificates) > 0 {
			certs, err = util.LoadServerCertificates(cfg.TLSCertificates)
			if err != nil {
				log.Printf("Warning: DoT 服务器无法加载配置的证书: %v", err)
				return nil
			}
		} else {
			certs, err = util.LoadServerCertificate("server.crt", "server.key")
			if err != nil {
				log.Printf("Warning: DoT 服务器无法加载默认证书: %v", err)
				return nil
			}
		}

		tlsConfig = &tls.Config{
			Certificates: certs,
			NextProtos:   []string{"dns", "h2", "http/1.1"},
		}
	}

	server := &dns.Server{
		Addr:         cfg.Listen.DOT,
		Net:          "tcp-tls",
		TLSConfig:    tlsConfig,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return &DoTServer{
		server: server,
		router: r,
		cfg:    cfg,
	}
}

func (s *DoTServer) Start() {
	if s.server == nil {
		log.Println("DoT 服务器未初始化，可能因为证书加载失败。")
		return
	}
	go func() {
		log.Printf("Starting DoT server on %s", s.server.Addr)
		err := s.server.ListenAndServe()
		if err != nil {
			log.Printf("无法启动DoT服务器: %v", err)
		}
	}()
}

func (s *DoTServer) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}
