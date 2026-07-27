package resolver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 缓存过期瞬间涌入的并发查询应合并为一次上游解析。
func TestLookupIPCoalescesConcurrentLookups(t *testing.T) {
	var calls int32
	release := make(chan struct{})

	b := NewBootstrapper([]string{"1.1.1.1:53"})
	b.resolve = func(ctx context.Context, host string) (string, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return "203.0.113.7", nil
	}

	const n = 50
	var wg sync.WaitGroup
	results := make([]string, n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = b.LookupIP(context.Background(), "dns.example")
		}(i)
	}

	// 等待所有 goroutine 进入等待状态后再放行。
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 upstream resolution, got %d", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("lookup %d failed: %v", i, errs[i])
		}
		if results[i] != "203.0.113.7" {
			t.Fatalf("lookup %d returned %q", i, results[i])
		}
	}

	// 后续查询应命中缓存，不再触发解析。
	if _, err := b.LookupIP(context.Background(), "dns.example"); err != nil {
		t.Fatalf("cached lookup failed: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected cache hit, got %d resolutions", got)
	}
}

// 解析暂时失败时应回退到宽限期内的旧记录。
func TestLookupIPFallsBackToStaleEntry(t *testing.T) {
	var fail atomic.Bool

	b := NewBootstrapper([]string{"1.1.1.1:53"})
	b.cacheTTL = 10 * time.Millisecond
	b.resolve = func(ctx context.Context, host string) (string, error) {
		if fail.Load() {
			return "", errors.New("bootstrap unavailable")
		}
		return "198.51.100.9", nil
	}

	ip, err := b.LookupIP(context.Background(), "dns.example")
	if err != nil || ip != "198.51.100.9" {
		t.Fatalf("initial lookup: ip=%q err=%v", ip, err)
	}

	time.Sleep(20 * time.Millisecond) // 让缓存过期
	fail.Store(true)

	ip, err = b.LookupIP(context.Background(), "dns.example")
	if err != nil {
		t.Fatalf("expected stale fallback, got error: %v", err)
	}
	if ip != "198.51.100.9" {
		t.Fatalf("expected stale IP, got %q", ip)
	}

	// 超出宽限期后必须如实报错，而非无限期返回旧值。
	b.staleTTL = 0
	if _, err := b.LookupIP(context.Background(), "dns.example"); err == nil {
		t.Fatal("expected error once stale grace period elapsed")
	}
}

// 首个请求者的 context 被取消不应影响其他等待者。
func TestLookupIPLeaderCancellationDoesNotAffectWaiters(t *testing.T) {
	release := make(chan struct{})
	b := NewBootstrapper([]string{"1.1.1.1:53"})
	b.resolve = func(ctx context.Context, host string) (string, error) {
		<-release
		return "192.0.2.5", nil
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := b.LookupIP(leaderCtx, "dns.example")
		leaderErr <- err
	}()

	time.Sleep(30 * time.Millisecond)

	waiterResult := make(chan string, 1)
	go func() {
		ip, err := b.LookupIP(context.Background(), "dns.example")
		if err != nil {
			waiterResult <- "err:" + err.Error()
			return
		}
		waiterResult <- ip
	}()

	time.Sleep(30 * time.Millisecond)
	cancelLeader()

	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected leader to observe cancellation, got %v", err)
	}

	close(release)

	select {
	case got := <-waiterResult:
		if got != "192.0.2.5" {
			t.Fatalf("waiter got %q, expected the resolved IP", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not complete after leader cancellation")
	}
}

func TestParseBootstrapServerDefaultsToUDP(t *testing.T) {
	server := parseBootstrapServer("8.8.8.8")

	if server.network != "udp" {
		t.Fatalf("expected udp network, got %q", server.network)
	}
	if server.address != "8.8.8.8:53" {
		t.Fatalf("expected default port to be appended, got %q", server.address)
	}
}

func TestParseBootstrapServerSupportsTCPPrefix(t *testing.T) {
	server := parseBootstrapServer("tcp://2001:4860:4860::8888")

	if server.network != "tcp" {
		t.Fatalf("expected tcp network, got %q", server.network)
	}
	if server.address != "[2001:4860:4860::8888]:53" {
		t.Fatalf("expected IPv6 address with default port, got %q", server.address)
	}
}

func TestNewBootstrapperSkipsEmptyEntries(t *testing.T) {
	bootstrapper := NewBootstrapper([]string{"", "  ", "1.1.1.1:53"})

	if len(bootstrapper.servers) != 1 {
		t.Fatalf("expected 1 bootstrap server, got %d", len(bootstrapper.servers))
	}
}
