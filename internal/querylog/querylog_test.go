package querylog

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGetStatsReportsRollingQPS(t *testing.T) {
	logger := NewQueryLogger(true, 10, 1, "", false)
	now := time.Now()

	logger.AddLog(&LogEntry{Time: now.Add(-12 * time.Second)})
	logger.AddLog(&LogEntry{Time: now.Add(-3 * time.Second)})
	logger.AddLog(&LogEntry{Time: now.Add(-2 * time.Second)})
	logger.AddLog(&LogEntry{Time: now.Add(-1 * time.Second)})

	stats := logger.GetStats()

	if stats.TotalQueries != 4 {
		t.Fatalf("expected 4 total queries, got %d", stats.TotalQueries)
	}

	if math.Abs(stats.QPS-0.3) > 0.05 {
		t.Fatalf("expected QPS close to 0.3, got %.3f", stats.QPS)
	}
}

func TestDisabledLoggerDropsLogs(t *testing.T) {
	logger := NewQueryLogger(false, 10, 1, "", false)

	logger.AddLog(&LogEntry{
		ClientIP: "127.0.0.1",
		Domain:   "example.com.",
		Upstream: "Rule(CN)",
		Status:   "NOERROR",
	})

	stats := logger.GetStats()
	if stats.TotalQueries != 0 {
		t.Fatalf("expected disabled logger to ignore queries, got %d", stats.TotalQueries)
	}

	logs, total := logger.GetLogs(0, 10, "")
	if len(logs) != 0 || total != 0 {
		t.Fatalf("expected disabled logger to return no logs, got len=%d total=%d", len(logs), total)
	}
}

func TestTopStatsTrackBoundedHistory(t *testing.T) {
	logger := NewQueryLogger(true, 2, 1, "", false)

	logger.AddLog(&LogEntry{ClientIP: "1.1.1.1", Domain: "first.example", Upstream: "Rule(CN)"})
	logger.AddLog(&LogEntry{ClientIP: "2.2.2.2", Domain: "second.example", Upstream: "Rule(CN)"})
	logger.AddLog(&LogEntry{ClientIP: "3.3.3.3", Domain: "third.example", Upstream: "Rule(Overseas)"})

	stats := logger.GetStats()
	if stats.TotalQueries != 3 {
		t.Fatalf("expected total queries to keep lifetime count, got %d", stats.TotalQueries)
	}
	if _, ok := stats.TopDomains["first.example"]; ok {
		t.Fatalf("expected evicted domain to be removed from bounded top stats")
	}
	if len(stats.TopDomains) != 2 {
		t.Fatalf("expected top domain stats to match bounded history, got %d entries", len(stats.TopDomains))
	}

	logs, total := logger.GetLogs(0, 10, "")
	if total != 2 {
		t.Fatalf("expected in-memory log history to be capped at 2, got %d", total)
	}
	if len(logs) != 2 || logs[0].Domain != "third.example" || logs[1].Domain != "second.example" {
		t.Fatalf("unexpected bounded log order: %#v", logs)
	}
}

// 环形缓冲区在多次回绕后仍须保持"最新在前"的顺序，
// 且分页、搜索、Top 统计都要与之一致。
func TestRingBufferWrapAround(t *testing.T) {
	const capacity = 4
	logger := NewQueryLogger(true, capacity, 1, "", false)

	// 写入 3 倍容量，强制多次回绕。
	for i := 0; i < capacity*3+1; i++ {
		logger.AddLog(&LogEntry{
			ClientIP: "10.0.0.1",
			Domain:   "d" + string(rune('a'+i)) + ".example",
			Upstream: "Rule(CN)",
		})
	}

	logs, total := logger.GetLogs(0, 10, "")
	if total != capacity {
		t.Fatalf("expected total=%d, got %d", capacity, total)
	}
	if len(logs) != capacity {
		t.Fatalf("expected %d logs, got %d", capacity, len(logs))
	}

	// 最后写入的是 i=12 -> 'm'，倒序应为 m, l, k, j。
	want := []string{"dm.example", "dl.example", "dk.example", "dj.example"}
	for i, w := range want {
		if logs[i].Domain != w {
			t.Fatalf("log[%d]: expected %q, got %q", i, w, logs[i].Domain)
		}
	}

	// ID 必须严格递减（最新在前）。
	for i := 1; i < len(logs); i++ {
		if logs[i-1].ID <= logs[i].ID {
			t.Fatalf("expected descending IDs, got %d then %d", logs[i-1].ID, logs[i].ID)
		}
	}

	// 分页跨越回绕点。
	page2, _ := logger.GetLogs(2, 2, "")
	if len(page2) != 2 || page2[0].Domain != "dk.example" || page2[1].Domain != "dj.example" {
		t.Fatalf("unexpected page 2: %#v", page2)
	}

	// 被淘汰的条目不得再出现在搜索结果里。
	old, oldTotal := logger.GetLogs(0, 10, "da.example")
	if len(old) != 0 || oldTotal != 0 {
		t.Fatalf("expected evicted entry to be unsearchable, got len=%d total=%d", len(old), oldTotal)
	}

	stats := logger.GetStats()
	if stats.TotalQueries != int64(capacity*3+1) {
		t.Fatalf("expected lifetime total %d, got %d", capacity*3+1, stats.TotalQueries)
	}
	if len(stats.TopDomains) != capacity {
		t.Fatalf("expected %d tracked domains, got %d", capacity, len(stats.TopDomains))
	}
	if stats.TopClients["10.0.0.1"] != int64(capacity) {
		t.Fatalf("expected client count %d, got %d", capacity, stats.TopClients["10.0.0.1"])
	}
}

// QPS 窗口用起始下标而非搬移来淘汰过期样本，需验证压缩前后一致。
func TestQPSWindowCompaction(t *testing.T) {
	logger := NewQueryLogger(true, 1000, 1, "", false)
	now := time.Now()

	// 30 条早已过期的样本，随后 5 条在窗口内。
	for i := 0; i < 30; i++ {
		logger.AddLog(&LogEntry{Time: now.Add(-60 * time.Second)})
	}
	for i := 0; i < 5; i++ {
		logger.AddLog(&LogEntry{Time: now.Add(-time.Duration(i) * time.Second)})
	}

	stats := logger.GetStats()
	if stats.TotalQueries != 35 {
		t.Fatalf("expected 35 total queries, got %d", stats.TotalQueries)
	}
	// 窗口内 5 条 / 10s = 0.5
	if math.Abs(stats.QPS-0.5) > 0.05 {
		t.Fatalf("expected QPS close to 0.5, got %.3f", stats.QPS)
	}

	logger.Clear()
	if qps := logger.GetStats().QPS; qps != 0 {
		t.Fatalf("expected QPS 0 after Clear, got %.3f", qps)
	}
}

func TestSaveToFileUsesBoundedWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	before := runtime.NumGoroutine()

	logger := NewQueryLogger(true, 32, 10, path, true)
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Fatalf("close logger: %v", err)
		}
	})

	for i := 0; i < 2000; i++ {
		logger.AddLog(&LogEntry{
			ClientIP: "127.0.0.1",
			Domain:   "example.com",
			Upstream: "Rule(CN)",
			Status:   "NOERROR",
		})
	}

	after := runtime.NumGoroutine()
	if delta := after - before; delta > 20 {
		t.Fatalf("expected bounded writer goroutines, got delta=%d (before=%d after=%d)", delta, before, after)
	}
}

func TestCloseFlushesQueuedLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	logger := NewQueryLogger(true, 32, 10, path, true)

	for i := 0; i < 50; i++ {
		logger.AddLog(&LogEntry{
			ClientIP: "127.0.0.1",
			Domain:   "flush.example",
			Upstream: "Rule(CN)",
			Status:   "NOERROR",
		})
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	if lines := strings.Count(string(data), "\n"); lines != 50 {
		t.Fatalf("expected 50 persisted lines, got %d", lines)
	}
}
