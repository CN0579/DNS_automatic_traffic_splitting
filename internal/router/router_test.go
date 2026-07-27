package router

import (
	"context"
	"net"
	"regexp"
	"testing"

	"doh-autoproxy/internal/client"
	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/querylog"

	"github.com/miekg/dns"
)

type fakeDNSClient struct {
	resp *dns.Msg
	err  error
}

func (f fakeDNSClient) Resolve(context.Context, *dns.Msg) (*dns.Msg, error) {
	if f.resp == nil {
		return nil, f.err
	}
	return f.resp.Copy(), f.err
}

func TestMatchNamesStripsLeadingUnderscoreLabels(t *testing.T) {
	tests := []struct {
		name     string
		qName    string
		expected []string
	}{
		{
			name:  "https service binding with port",
			qName: "_8084._https.xxjsbigdata.scbdc.edu.cn.",
			expected: []string{
				"_8084._https.xxjsbigdata.scbdc.edu.cn",
				"_https.xxjsbigdata.scbdc.edu.cn",
				"xxjsbigdata.scbdc.edu.cn",
			},
		},
		{
			name:  "acme challenge",
			qName: "_acme-challenge.example.com",
			expected: []string{
				"_acme-challenge.example.com",
				"example.com",
			},
		},
		{
			name:  "regular hostname",
			qName: "www.example.com.",
			expected: []string{
				"www.example.com",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := matchNames(tc.qName)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %d names, got %d: %v", len(tc.expected), len(got), got)
			}
			for i := range tc.expected {
				if got[i] != tc.expected[i] {
					t.Fatalf("expected names %v, got %v", tc.expected, got)
				}
			}
		})
	}
}

func TestRouteInternalMatchesRuleForHTTPSServiceName(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("_8084._https.xxjsbigdata.scbdc.edu.cn.", dns.TypeHTTPS)

	overseasResp := new(dns.Msg)
	overseasResp.SetReply(req)

	r := &Router{
		config: &config.Config{
			Rules: map[string]string{
				"xxjsbigdata.scbdc.edu.cn": "overseas",
			},
			Hosts: map[string]string{},
		},
		overseasClients: []client.DNSClient{
			fakeDNSClient{resp: overseasResp},
		},
	}

	resp, upstream, err := r.routeInternal(context.Background(), req)
	if err != nil {
		t.Fatalf("routeInternal returned error: %v", err)
	}
	if upstream != "Rule(Overseas)" {
		t.Fatalf("expected Rule(Overseas), got %q", upstream)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful response, got %#v", resp)
	}
}

func TestRouteInternalMatchesRegexForServiceNameAlias(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("_xmpp-client._tcp.example.com.", dns.TypeSRV)

	cnResp := new(dns.Msg)
	cnResp.SetReply(req)

	r := &Router{
		config: &config.Config{
			Rules: map[string]string{},
			Hosts: map[string]string{},
		},
		regexRules: []RegexRule{
			{
				Pattern: regexp.MustCompile(`^example\.com$`),
				Target:  "cn",
			},
		},
		cnClients: []client.DNSClient{
			fakeDNSClient{resp: cnResp},
		},
	}

	resp, upstream, err := r.routeInternal(context.Background(), req)
	if err != nil {
		t.Fatalf("routeInternal returned error: %v", err)
	}
	if upstream != "Rule(Regex/CN)" {
		t.Fatalf("expected Rule(Regex/CN), got %q", upstream)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful response, got %#v", resp)
	}
}

func TestHostOverrideOnlyAppliesToAddressQueries(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeHTTPS)

	resp, ok := hostOverrideResponse(req, net.ParseIP("1.2.3.4"))
	if ok {
		t.Fatalf("expected HTTPS query not to be answered by hosts override, got %#v", resp)
	}
}

func TestRouteConvertsServiceBindingNXDOMAINToNoDataWhenOriginExists(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("_7826._https.broadcast.chat.bilibili.com.", dns.TypeHTTPS)

	nxResp := new(dns.Msg)
	nxResp.SetRcode(req, dns.RcodeNameError)

	r := &Router{
		config: &config.Config{
			Rules: map[string]string{
				"broadcast.chat.bilibili.com": "cn",
			},
			Hosts: map[string]string{
				"broadcast.chat.bilibili.com": "1.2.3.4",
			},
		},
		cnClients: []client.DNSClient{
			fakeDNSClient{resp: nxResp},
		},
	}

	resp, err := r.Route(context.Background(), req, "127.0.0.1")
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected a DNS response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR after compatibility rewrite, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected empty answer section, got %d records", len(resp.Answer))
	}
	if len(resp.Ns) != 0 {
		t.Fatalf("expected no authority section, got %d records", len(resp.Ns))
	}
}

func TestRouteKeepsServiceBindingNXDOMAINWhenOriginMissing(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("_7826._https.broadcast.chat.bilibili.com.", dns.TypeHTTPS)

	nxResp := new(dns.Msg)
	nxResp.SetRcode(req, dns.RcodeNameError)

	r := &Router{
		config: &config.Config{
			Rules: map[string]string{
				"broadcast.chat.bilibili.com": "cn",
			},
			Hosts: map[string]string{},
		},
		cnClients: []client.DNSClient{
			fakeDNSClient{resp: nxResp},
		},
	}

	resp, err := r.Route(context.Background(), req, "127.0.0.1")
	if err != nil {
		t.Fatalf("Route returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected a DNS response")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN to be preserved, got %d", resp.Rcode)
	}
}

// NXDOMAIN 的负缓存处理不得清零 OPT 记录的 TTL 字段——
// 该字段编码的是扩展 RCODE / EDNS 版本 / DO 位，而非存活时间。
func TestNXDOMAINPreservesEDNSFlags(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.", dns.TypeA)
	req.SetEdns0(4096, true)

	upstreamResp := new(dns.Msg)
	upstreamResp.SetRcode(req, dns.RcodeNameError)
	upstreamResp.SetEdns0(4096, true)
	// 附带一条普通 SOA，用于确认非 OPT 记录仍会被清零。
	soa, err := dns.NewRR("example. 3600 IN SOA ns.example. root.example. 1 2 3 4 5")
	if err != nil {
		t.Fatal(err)
	}
	upstreamResp.Ns = append(upstreamResp.Ns, soa)

	cfg := &config.Config{
		Hosts: map[string]string{},
		Rules: map[string]string{"nonexistent.example": "cn"},
	}
	r := NewRouter(cfg, nil, nil)
	r.cnClients = []client.DNSClient{fakeDNSClient{resp: upstreamResp}}

	resp, err := r.Route(context.Background(), req, "127.0.0.1")
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}

	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT record to survive")
	}
	if !opt.Do() {
		t.Fatal("DO bit was cleared by negative-cache TTL zeroing")
	}
	if opt.UDPSize() != 4096 {
		t.Fatalf("expected UDP size 4096, got %d", opt.UDPSize())
	}

	// 非 OPT 记录仍应被清零以避免负缓存。
	if len(resp.Ns) != 1 {
		t.Fatalf("expected 1 authority record, got %d", len(resp.Ns))
	}
	if resp.Ns[0].Header().Ttl != 0 {
		t.Fatalf("expected authority TTL zeroed, got %d", resp.Ns[0].Header().Ttl)
	}
}

// 上游返回 (nil, nil) 时不得 panic。
func TestRaceResolveHandlesNilResponse(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	_, err := client.RaceResolve(context.Background(), req,
		[]client.DNSClient{fakeDNSClient{resp: nil, err: nil}})
	if err == nil {
		t.Fatal("expected an error for a nil upstream response, got nil")
	}
}

// TestRouteNeverReturnsNilResponseWithNilError 锁定 Route 的调用契约：
// err==nil 时 resp 必须非 nil。DNS/DoT/DoH/DoQ 四个处理器在 err==nil 分支都会
// 直接解引用 resp（Truncate/Pack/WriteMsg），返回 (nil, nil) 会让整个进程崩溃。
//
// 当前该契约由 RaceResolve 的判空 + routeInternal/Route 的兜底共同保证。
// 本测试防止后续改动移除其中任何一层后契约被悄悄打破。
func TestRouteNeverReturnsNilResponseWithNilError(t *testing.T) {
	cfg := &config.Config{
		Hosts: map[string]string{},
		Rules: map[string]string{},
	}
	cfg.QueryLog.Enabled = false

	r := &Router{
		config: cfg,
		logger: querylog.NewQueryLogger(false, 10, 1, "", false),
	}
	// 两侧上游都返回 (nil resp, nil err)——这是旧代码走到
	// "return nil, "GeoIP(Error)", cnResult.err" 时的实际情形。
	r.cnClients = []client.DNSClient{fakeDNSClient{resp: nil, err: nil}}
	r.overseasClients = []client.DNSClient{fakeDNSClient{resp: nil, err: nil}}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, err := r.Route(context.Background(), req, "127.0.0.1")
	if err == nil && resp == nil {
		t.Fatal("Route 返回了 (nil, nil)：调用方会在解引用 resp 时 panic")
	}
	if err == nil {
		t.Fatalf("期望返回错误，got resp=%v", resp)
	}
}
