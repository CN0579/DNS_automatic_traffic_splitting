package client

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type raceResult struct {
	resp *dns.Msg
	err  error
}

func RaceResolve(ctx context.Context, req *dns.Msg, clients []DNSClient) (*dns.Msg, error) {
	if len(clients) == 0 {
		return nil, fmt.Errorf("没有可用的上游客户端")
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan raceResult, len(clients))

	for _, c := range clients {
		reqClone := req.Copy()
		go func(cl DNSClient) {
			resp, err := cl.Resolve(raceCtx, reqClone)
			results <- raceResult{resp: resp, err: err}
		}(c)
	}

	var (
		bestFail *dns.Msg // 保存 SERVFAIL/NXDOMAIN 等非成功响应作为备选
		lastErr  error
	)

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for i := 0; i < len(clients); i++ {
		select {
		case r := <-results:
			if r.err != nil {
				lastErr = r.err
				continue
			}
			// 真正成功的响应（NOERROR），立即返回
			if r.resp.Rcode == dns.RcodeSuccess {
				return r.resp, nil
			}
			// NXDOMAIN / SERVFAIL 等：保存但继续等其他上游
			if bestFail == nil {
				bestFail = r.resp
			}
		case <-timer.C:
			// 超时，返回已有的最佳结果
			if bestFail != nil {
				return bestFail, nil
			}
			return nil, fmt.Errorf("并发查询超时")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// 所有上游都返回了，优先返回非成功但合法的 DNS 响应
	if bestFail != nil {
		return bestFail, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("所有上游查询均失败: %w", lastErr)
	}
	return nil, fmt.Errorf("未知错误：未收到任何响应")
}
