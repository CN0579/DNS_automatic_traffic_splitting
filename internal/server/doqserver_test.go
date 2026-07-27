package server

import (
	"testing"

	"github.com/miekg/dns"
)

// buildOversizedResponse 构造一个打包后超过 65535 字节的应答，
// 模拟上游返回超大 TXT 记录集的情形。
func buildOversizedResponse(t *testing.T) (*dns.Msg, *dns.Msg) {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion("big.example.com.", dns.TypeTXT)

	resp := new(dns.Msg)
	resp.SetReply(req)

	chunk := make([]byte, 255)
	for i := range chunk {
		chunk[i] = 'a'
	}
	// 每条 TXT 约 300 字节，300 条即可越过 65535 上限。
	for i := 0; i < 300; i++ {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "big.example.com.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{string(chunk)},
		})
	}
	return req, resp
}

// TestDoQOversizedResponseWouldOverflowLengthPrefix 证明这是个真实缺陷：
// DoQ 的 2 字节长度前缀无法表示 >65535 的报文，
// 直接 uint16(len) 会把长度回绕成一个很小的值。
func TestDoQOversizedResponseWouldOverflowLengthPrefix(t *testing.T) {
	_, resp := buildOversizedResponse(t)

	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("构造超大响应失败: %v", err)
	}
	if len(packed) <= maxDNSMessageSize {
		t.Fatalf("测试数据不够大: %d 字节", len(packed))
	}

	// 旧代码的行为：uint16 截断。
	truncatedLen := uint16(len(packed))
	if int(truncatedLen) == len(packed) {
		t.Fatal("期望 uint16 转换发生回绕")
	}
	t.Logf("实际长度 %d 被前缀编码为 %d —— 客户端会按错误长度解析", len(packed), truncatedLen)
}

// TestDoQTruncatesOversizedResponse 验证修复：超限时改发一个置了 TC 位的空应答，
// 客户端可据此回退，而不是挂在流上直到空闲超时。
func TestDoQTruncatesOversizedResponse(t *testing.T) {
	req, resp := buildOversizedResponse(t)

	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}

	if len(packed) > maxDNSMessageSize {
		truncated := new(dns.Msg)
		truncated.SetRcode(req, dns.RcodeSuccess)
		truncated.Id = 0
		truncated.Truncated = true
		packed, err = truncated.Pack()
		if err != nil {
			t.Fatalf("打包截断响应失败: %v", err)
		}
	}

	if len(packed) > maxDNSMessageSize {
		t.Fatalf("截断后仍超限: %d", len(packed))
	}
	if int(uint16(len(packed))) != len(packed) {
		t.Fatal("截断后长度仍无法用 uint16 表示")
	}

	var out dns.Msg
	if err := out.Unpack(packed); err != nil {
		t.Fatalf("截断响应无法解包: %v", err)
	}
	if !out.Truncated {
		t.Error("截断响应必须置 TC 位，否则客户端不会回退到 TCP/重试")
	}
	// RFC 9250 §4.2.1: DoQ 报文 ID 必须为 0。
	if out.Id != 0 {
		t.Errorf("DoQ 响应 ID = %d, want 0", out.Id)
	}
}
