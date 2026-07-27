package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type cacheEntry struct {
	ip     string
	expiry time.Time
}

// inflight 用于合并同一域名的并发解析请求。
type inflight struct {
	done chan struct{}
	ip   string
	err  error
}

type bootstrapServer struct {
	network string
	address string
}

func (s bootstrapServer) String() string {
	if s.network == "" || s.network == "udp" {
		return s.address
	}
	return s.network + "://" + s.address
}

type Bootstrapper struct {
	servers  []bootstrapServer
	counter  uint64
	cache    sync.Map
	pending  sync.Map
	cacheTTL time.Duration
	// staleTTL 为过期条目的宽限期：上游解析暂时失败时，
	// 宁可复用略旧的 IP，也好过让所有上游同时不可用。
	staleTTL time.Duration
	// resolve 供测试注入；为空时使用 lookupWithRetry。
	resolve func(ctx context.Context, host string) (string, error)
}

func (b *Bootstrapper) resolveHost(ctx context.Context, host string) (string, error) {
	if b.resolve != nil {
		return b.resolve(ctx, host)
	}
	return b.lookupWithRetry(ctx, host)
}

func NewBootstrapper(servers []string) *Bootstrapper {
	normalized := make([]bootstrapServer, 0, len(servers))
	for _, s := range servers {
		parsed := parseBootstrapServer(s)
		if parsed.address == "" {
			continue
		}
		normalized = append(normalized, parsed)
	}
	return &Bootstrapper{
		servers:  normalized,
		cacheTTL: 5 * time.Minute,
		staleTTL: 1 * time.Hour,
	}
}

func parseBootstrapServer(server string) bootstrapServer {
	raw := strings.TrimSpace(server)
	if raw == "" {
		return bootstrapServer{}
	}

	network := "udp"
	if idx := strings.Index(raw, "://"); idx >= 0 {
		switch strings.ToLower(raw[:idx]) {
		case "tcp":
			network = "tcp"
		case "udp":
			network = "udp"
		}
		raw = strings.TrimSpace(raw[idx+3:])
	}

	if raw == "" {
		return bootstrapServer{}
	}

	if _, _, err := net.SplitHostPort(raw); err != nil {
		raw = net.JoinHostPort(raw, "53")
	}

	return bootstrapServer{
		network: network,
		address: raw,
	}
}

func (b *Bootstrapper) LookupIP(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// 查缓存：过期条目先保留，解析失败时可作为兜底。
	var stale *cacheEntry
	if entry, ok := b.cache.Load(host); ok {
		ce := entry.(*cacheEntry)
		if time.Now().Before(ce.expiry) {
			return ce.ip, nil
		}
		stale = ce
	}

	ip, err := b.lookupOnce(ctx, host)
	if err != nil {
		// 解析失败时回退到宽限期内的旧记录：短暂的 bootstrap 抖动
		// 不应让所有上游同时不可用。
		if stale != nil && time.Now().Before(stale.expiry.Add(b.staleTTL)) {
			return stale.ip, nil
		}
		b.cache.Delete(host)
		return "", err
	}

	return ip, nil
}

// lookupOnce 合并同一域名的并发解析：缓存过期瞬间可能有数十个查询
// 同时到达，各自发起一次耗时数秒的 bootstrap 解析纯属浪费。
func (b *Bootstrapper) lookupOnce(ctx context.Context, host string) (string, error) {
	fl := &inflight{done: make(chan struct{})}
	actual, loaded := b.pending.LoadOrStore(host, fl)
	if loaded {
		leader := actual.(*inflight)
		select {
		case <-leader.done:
			return leader.ip, leader.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	// 本 goroutine 为首个请求者，负责实际解析。
	// 使用独立的 context，避免首个请求者被取消后
	// 拖累所有等待者。
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	go func() {
		defer cancel()
		defer b.pending.Delete(host)
		defer close(fl.done)

		fl.ip, fl.err = b.resolveHost(lookupCtx, host)
		if fl.err == nil {
			b.cache.Store(host, &cacheEntry{
				ip:     fl.ip,
				expiry: time.Now().Add(b.cacheTTL),
			})
		}
	}()

	select {
	case <-fl.done:
		return fl.ip, fl.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (b *Bootstrapper) lookupWithRetry(ctx context.Context, host string) (string, error) {
	if len(b.servers) == 0 {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("no IP found for %s", host)
		}
		return ips[0].String(), nil
	}

	// 从当前轮询位置开始，依次尝试所有 bootstrap 服务器
	startIdx := atomic.AddUint64(&b.counter, 1)
	var lastErr error

	for i := 0; i < len(b.servers); i++ {
		server := b.servers[(startIdx+uint64(i))%uint64(len(b.servers))]

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 3 * time.Second,
				}
				return d.DialContext(ctx, server.network, server.address)
			},
		}

		resolveCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ips, err := r.LookupIPAddr(resolveCtx, host)
		cancel()

		if err != nil {
			lastErr = fmt.Errorf("bootstrap %s failed: %w", server, err)
			continue
		}
		if len(ips) == 0 {
			lastErr = fmt.Errorf("no IP found for %s via bootstrap %s", host, server)
			continue
		}

		return ips[0].String(), nil
	}

	return "", fmt.Errorf("all bootstrap servers failed for %s: %w", host, lastErr)
}
