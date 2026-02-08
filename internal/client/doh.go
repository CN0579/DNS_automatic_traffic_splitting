package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/resolver"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type DoHClient struct {
	cfg          config.UpstreamServer
	bootstrapper *resolver.Bootstrapper
	httpClient   *http.Client
}

func NewDoHClient(cfg config.UpstreamServer, b *resolver.Bootstrapper) *DoHClient {
	client := &DoHClient{
		cfg:          cfg,
		bootstrapper: b,
	}
	client.initHTTPClient()
	return client
}

func (c *DoHClient) initHTTPClient() {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.cfg.InsecureSkipVerify,
	}

	if c.cfg.EnableH3 {
		c.httpClient = &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig: tlsConfig,
				QUICConfig: &quic.Config{
					MaxIdleTimeout: 30 * time.Second,
				},
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					host, port, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					ip, err := c.bootstrapper.LookupIP(ctx, host)
					if err != nil {
						return nil, fmt.Errorf("H3 bootstrap解析失败: %w", err)
					}
					resolvedAddr := net.JoinHostPort(ip, port)
					udpAddr, err := net.ResolveUDPAddr("udp", resolvedAddr)
					if err != nil {
						return nil, err
					}
					udpConn, err := net.ListenUDP("udp", nil)
					if err != nil {
						return nil, err
					}
					tr := &quic.Transport{Conn: udpConn}
					return tr.Dial(ctx, udpAddr, tlsCfg, cfg)
				},
			},
			Timeout: 10 * time.Second,
		}
		return
	}

	c.httpClient = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ip, err := c.bootstrapper.LookupIP(ctx, host)
				if err != nil {
					return nil, err
				}
				d := net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsConfig,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
}

func (c *DoHClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ensureECS(req, c.cfg.ECSIP)

	msgBuf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("打包DNS消息失败: %w", err)
	}

	urlStr := c.cfg.Address
	if !strings.HasPrefix(urlStr, "https://") && !strings.HasPrefix(urlStr, "http://") {
		urlStr = "https://" + urlStr
	}

	if u, err := url.Parse(urlStr); err == nil {
		if u.Path == "" || u.Path == "/" {
			u.Path = "/dns-query"
			urlStr = u.String()
		}
	} else {
		slashIdx := strings.Index(strings.TrimPrefix(urlStr, "https://"), "/")
		if slashIdx == -1 {
			urlStr += "/dns-query"
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(msgBuf))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")

	resp, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("DoH HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("DoH请求返回非OK状态码: %d, 响应体: %s", resp.StatusCode, string(bodyBytes))
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取DoH响应体失败: %w", err)
	}

	responseMsg := new(dns.Msg)
	err = responseMsg.Unpack(respBody)
	if err != nil {
		return nil, fmt.Errorf("解包DoH响应消息失败: %w", err)
	}

	return responseMsg, nil
}
