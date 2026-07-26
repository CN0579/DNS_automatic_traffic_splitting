package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/router"
	"doh-autoproxy/internal/util"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type DoQServer struct {
	addr     string
	router   *router.Router
	cfg      *config.Config
	cm       *util.CertManager
	listener *quic.Listener
	wg       sync.WaitGroup
}

func NewDoQServer(cfg *config.Config, r *router.Router, cm *util.CertManager) *DoQServer {
	return &DoQServer{
		addr:   cfg.Listen.DOQAddr(),
		router: r,
		cfg:    cfg,
		cm:     cm,
	}
}

func (s *DoQServer) Start() {
	var tlsConfig *tls.Config

	if s.cm != nil && s.cm.GetCertificateFunc() != nil {
		log.Println("DoQ: Using AutoCert for TLS")
		tlsConfig = &tls.Config{
			GetCertificate: s.cm.GetCertificateFunc(),
			NextProtos:     []string{"doq"},
		}
	} else {
		var certs []tls.Certificate
		var err error

		if len(s.cfg.TLSCertificates) > 0 {
			certs, err = util.LoadServerCertificates(s.cfg.TLSCertificates)
			if err != nil {
				log.Printf("Warning: DoQ 服务器无法加载配置的证书: %v", err)
				return
			}
		} else {
			certs, err = util.LoadServerCertificate("server.crt", "server.key")
			if err != nil {
				log.Printf("Warning: DoQ 服务器无法加载默认证书: %v", err)
				return
			}
		}

		tlsConfig = &tls.Config{
			Certificates: certs,
			NextProtos:   []string{"doq"},
		}
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}

	// 同步创建监听器：若在 goroutine 中赋值 s.listener，
	// Stop() 可能读到 nil 而无法关闭，导致 accept 循环泄漏、端口占用。
	log.Printf("Starting DoQ server on %s", s.addr)
	listener, err := quic.ListenAddr(s.addr, tlsConfig, quicConfig)
	if err != nil {
		log.Printf("无法启动DoQ服务器: %v", err)
		return
	}
	s.listener = listener

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				if !errors.Is(err, quic.ErrServerClosed) {
					log.Printf("接受QUIC连接失败: %v", err)
				}
				return
			}
			go s.handleQuicConnection(conn)
		}
	}()
}

func (s *DoQServer) Stop() error {
	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()

	// 等待 accept 循环退出，确保 UDP 端口在 reload 重新绑定前已释放；
	// 否则重启会以 EADDRINUSE 失败，DoQ 服务静默消失。
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Printf("Warning: DoQ accept 循环未在超时前退出")
	}

	return err
}

func (s *DoQServer) handleQuicConnection(conn *quic.Conn) {
	defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "Connection closed")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			// 客户端正常关闭连接/空闲超时是常态，不作为错误记录。
			var appErr *quic.ApplicationError
			var idleErr *quic.IdleTimeoutError
			if !errors.As(err, &appErr) && !errors.As(err, &idleErr) {
				log.Printf("DoQ: 接受流失败: %v", err)
			}
			return
		}
		go s.handleQuicStream(stream, conn.RemoteAddr())
	}
}

func (s *DoQServer) handleQuicStream(stream *quic.Stream, remoteAddr net.Addr) {
	defer stream.Close()

	// 防止半开流无限占用资源。
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))

	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(stream, lengthBytes); err != nil {
		if err != io.EOF {
			log.Printf("DoQ: 读取DNS消息长度失败: %v", err)
		}
		return
	}
	dnsMsgLen := binary.BigEndian.Uint16(lengthBytes)
	// 长度为 0 时 ReadFull 立即成功并返回空切片，随后 Unpack 报错；
	// 提前返回可省掉一次无意义的分配与日志噪音。
	if dnsMsgLen == 0 {
		return
	}

	msgBuf := make([]byte, dnsMsgLen)
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		log.Printf("DoQ: 读取DNS消息失败: %v", err)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(msgBuf); err != nil {
		log.Printf("DoQ: 解包DNS消息失败: %v", err)
		return
	}

	if len(req.Question) == 0 {
		log.Printf("DoQ: 收到空问题查询 from %s", remoteAddr)
		return
	}

	qName := strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))

	clientIP, _, _ := net.SplitHostPort(remoteAddr.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := s.router.Route(ctx, req, clientIP)
	if err != nil {
		log.Printf("DoQ: Error routing DNS query for %s: %v", qName, err)
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}

	// RFC 9250 §4.2.1: DoQ 报文的 Message ID 必须为 0。
	resp.Id = 0

	packedResp, err := resp.Pack()
	if err != nil {
		log.Printf("DoQ: 打包响应消息失败: %v", err)
		return
	}

	// 2 字节长度前缀无法表示超过 65535 的报文；直接写出会把长度截断，
	// 客户端将按错误的长度解析并挂在流上，直到空闲超时。
	if len(packedResp) > maxDNSMessageSize {
		truncated := new(dns.Msg)
		truncated.SetRcode(req, dns.RcodeSuccess)
		truncated.Id = 0
		truncated.Truncated = true
		packedResp, err = truncated.Pack()
		if err != nil {
			log.Printf("DoQ: 打包截断响应失败: %v", err)
			return
		}
	}

	// 单次写出长度前缀与消息体，避免被拆成两个 QUIC 帧。
	out := make([]byte, 2, 2+len(packedResp))
	binary.BigEndian.PutUint16(out, uint16(len(packedResp)))
	out = append(out, packedResp...)

	if _, err := stream.Write(out); err != nil {
		log.Printf("DoQ: 写入响应失败: %v", err)
		return
	}
}
