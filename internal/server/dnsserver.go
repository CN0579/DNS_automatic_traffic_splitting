package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/router"

	"github.com/miekg/dns"
)

type DNSServer struct {
	udpServer *dns.Server
	tcpServer *dns.Server
	router    *router.Router
}

func NewDNSServer(cfg *config.Config, r *router.Router) *DNSServer {
	handler := &DNSRequestHandler{router: r}

	var udpServer, tcpServer *dns.Server

	if addr := cfg.Listen.DNSUDPAddr(); addr != "" {
		udpServer = &dns.Server{Addr: addr, Net: "udp", Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	}

	if addr := cfg.Listen.DNSTCPAddr(); addr != "" {
		tcpServer = &dns.Server{Addr: addr, Net: "tcp", Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	}

	return &DNSServer{
		udpServer: udpServer,
		tcpServer: tcpServer,
		router:    r,
	}
}

func (s *DNSServer) Start() {
	if s.udpServer != nil {
		go func() {
			log.Printf("Starting UDP DNS server on %s", s.udpServer.Addr)
			err := s.udpServer.ListenAndServe()
			if err != nil {
				log.Printf("无法启动UDP DNS服务器: %v", err)
			}
		}()
	}

	if s.tcpServer != nil {
		go func() {
			log.Printf("Starting TCP DNS server on %s", s.tcpServer.Addr)
			err := s.tcpServer.ListenAndServe()
			if err != nil {
				log.Printf("无法启动TCP DNS服务器: %v", err)
			}
		}()
	}
}

func (s *DNSServer) Stop() error {
	// 两个监听器都必须尝试关闭：旧实现在 UDP 关闭失败时直接返回，
	// 会把 TCP 监听器泄漏下去并占住端口，导致后续 reload 无法重新绑定。
	var errs []error
	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("UDP: %w", err))
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("TCP: %w", err))
		}
	}
	return errors.Join(errs...)
}

type DNSRequestHandler struct {
	router *router.Router
}

func (h *DNSRequestHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	qName := strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))

	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := h.router.Route(ctx, req, clientIP)
	if err != nil {
		log.Printf("Error routing DNS query for %s: %v", qName, err)
		dns.HandleFailed(w, req)
		return
	}

	// UDP 上超出客户端通告尺寸的应答必须截断并置 TC 位（RFC 1035 §4.2.1、
	// RFC 6891 §6.2.4），否则 Pack 失败、客户端只能等待超时。
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		resp.Truncate(udpResponseSize(req))
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("Error writing DNS response for %s: %v", qName, err)
	}
}

// udpResponseSize 返回客户端可接收的最大 UDP 应答尺寸。
func udpResponseSize(req *dns.Msg) int {
	if opt := req.IsEdns0(); opt != nil {
		if size := int(opt.UDPSize()); size >= dns.MinMsgSize {
			return size
		}
	}
	return dns.MinMsgSize
}
