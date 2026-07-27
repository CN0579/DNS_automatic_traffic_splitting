package server

import (
	"net"
	"testing"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/router"

	"github.com/miekg/dns"
)

type captureResponseWriter struct {
	msg *dns.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 53}
}

func (w *captureResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (w *captureResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg.Copy()
	return nil
}

func (w *captureResponseWriter) Write(buf []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(buf); err != nil {
		return 0, err
	}
	w.msg = msg
	return len(buf), nil
}

func (w *captureResponseWriter) Close() error {
	return nil
}

func (w *captureResponseWriter) TsigStatus() error {
	return nil
}

func (w *captureResponseWriter) TsigTimersOnly(bool) {}

func (w *captureResponseWriter) Hijack() {}

func TestServeDNSPreservesAnswersFromRouter(t *testing.T) {
	cfg := &config.Config{
		Hosts: map[string]string{
			"example.com": "1.2.3.4",
		},
		Rules: map[string]string{},
	}

	handler := &DNSRequestHandler{
		router: router.NewRouter(cfg, nil, nil),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	writer := &captureResponseWriter{}
	handler.ServeDNS(writer, req)

	if writer.msg == nil {
		t.Fatal("expected a DNS response")
	}
	if writer.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", writer.msg.Rcode)
	}
	if len(writer.msg.Answer) != 1 {
		t.Fatalf("expected one answer, got %d", len(writer.msg.Answer))
	}

	a, ok := writer.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", writer.msg.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("1.2.3.4").To4()) {
		t.Fatalf("expected 1.2.3.4, got %s", a.A)
	}
}

func TestUDPResponseSize(t *testing.T) {
	plain := new(dns.Msg)
	plain.SetQuestion("example.com.", dns.TypeA)
	if got := udpResponseSize(plain); got != dns.MinMsgSize {
		t.Fatalf("no-EDNS query: expected %d, got %d", dns.MinMsgSize, got)
	}

	edns := new(dns.Msg)
	edns.SetQuestion("example.com.", dns.TypeA)
	edns.SetEdns0(4096, false)
	if got := udpResponseSize(edns); got != 4096 {
		t.Fatalf("EDNS 4096: expected 4096, got %d", got)
	}

	// 客户端通告的尺寸小于协议下限时必须夹到 512。
	tiny := new(dns.Msg)
	tiny.SetQuestion("example.com.", dns.TypeA)
	tiny.SetEdns0(128, false)
	if got := udpResponseSize(tiny); got != dns.MinMsgSize {
		t.Fatalf("EDNS 128: expected %d, got %d", dns.MinMsgSize, got)
	}
}

func TestTruncationSetsTCBit(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	// 塞入远超 512 字节的应答。
	for i := 0; i < 200; i++ {
		rr, err := dns.NewRR("example.com. 300 IN A 93.184.216.34")
		if err != nil {
			t.Fatal(err)
		}
		resp.Answer = append(resp.Answer, rr)
	}

	full, err := resp.Pack()
	if err != nil {
		t.Fatalf("packing oversized response: %v", err)
	}
	if len(full) <= dns.MinMsgSize {
		t.Fatalf("test setup: expected >512 bytes, got %d", len(full))
	}

	resp.Truncate(udpResponseSize(req))

	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("packing truncated response: %v", err)
	}
	if len(packed) > dns.MinMsgSize {
		t.Fatalf("expected <=512 bytes after truncation, got %d", len(packed))
	}
	if !resp.Truncated {
		t.Fatal("expected TC bit to be set")
	}
}

func TestNoTruncationForSmallResponse(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, err := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}
	resp.Answer = append(resp.Answer, rr)

	resp.Truncate(udpResponseSize(req))

	if resp.Truncated {
		t.Fatal("small response must not be marked truncated")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected answer preserved, got %d records", len(resp.Answer))
	}
}
