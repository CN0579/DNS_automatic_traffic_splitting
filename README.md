<p align="center">
  <h1 align="center">DNS Automatic Traffic Splitting</h1>
  <p align="center">
    高性能 · 多协议 · 智能分流 · 可视化管理
    <br />
    <em>一个使用 Go 编写的现代化 DNS 代理服务，自动根据 GeoIP/GeoSite 智能分流国内外流量</em>
  </p>
  <p align="center">
    <a href="https://github.com/Hamster-Prime/DNS_automatic_traffic_splitting/actions/workflows/release.yml"><img src="https://github.com/Hamster-Prime/DNS_automatic_traffic_splitting/actions/workflows/release.yml/badge.svg" alt="Build Status" /></a>
    <a href="https://github.com/Hamster-Prime/DNS_automatic_traffic_splitting/actions/workflows/docker.yml"><img src="https://github.com/Hamster-Prime/DNS_automatic_traffic_splitting/actions/workflows/docker.yml/badge.svg" alt="Docker Image" /></a>
    <a href="https://hub.docker.com/r/weijiaqaq/dns_automatic_traffic_splitting"><img src="https://img.shields.io/docker/pulls/weijiaqaq/dns_automatic_traffic_splitting?color=blue&logo=docker&logoColor=white" alt="Docker Pulls" /></a>
    <a href="https://github.com/Hamster-Prime/DNS_automatic_traffic_splitting/releases"><img src="https://img.shields.io/github/v/release/Hamster-Prime/DNS_automatic_traffic_splitting?color=brightgreen&logo=github" alt="Latest Release" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" /></a>
  </p>
</p>

---

## 为什么选择这个项目？

在中国大陆的网络环境下，DNS 解析面临独特的挑战：国内域名需要国内 DNS 获得最优 CDN 节点，海外域名需要海外 DNS 避免污染。手动维护分流规则既繁琐又不可靠。

**DNS Automatic Traffic Splitting** 通过 GeoIP + GeoSite 数据库实现全自动智能分流，同时提供现代化 Web 面板进行可视化管理，让 DNS 配置变得简单而强大。

### 核心亮点

| 特性 | 说明 |
|:---|:---|
| **全协议覆盖** | UDP / TCP / DoT / DoQ / DoH (HTTP/2 + HTTP/3) 一站式支持 |
| **智能分流引擎** | GeoSite 域名匹配 → GeoIP 结果验证 → 双路并发兜底，三级策略确保准确 |
| **并发竞速** | 多上游同时查询，最快成功者胜出，SERVFAIL 不会抢占正确结果 |
| **Bootstrap 解析** | 内置独立引导解析器，带缓存和多服务器重试，避免循环依赖 |
| **ECS 优化** | 自动附加 EDNS Client Subnet，让 CDN 返回最近节点 |
| **连接复用** | TCP/DoT 支持 Pipelining (RFC 7766)，DoH 支持 HTTP/3 (QUIC) |
| **自动证书** | 集成 Let's Encrypt，配置域名即可自动申请和续期 TLS 证书 |
| **Web 管理面板** | Liquid Glass 拟态风格，深色/浅色模式，完美适配移动端 |
| **自动更新** | 启动时自动拉取最新 GeoIP.dat / GeoSite.dat |

---

## 快速开始

### 一键安装 (Linux)

```bash
bash <(curl -sL https://raw.githubusercontent.com/Hamster-Prime/DNS_automatic_traffic_splitting/main/install.sh)
```

脚本自动完成：下载最新二进制 → 创建配置目录 → 注册 Systemd 服务 → 开机自启。

支持架构：`amd64` / `arm64`

### Docker 部署

**Docker CLI：**

```bash
docker run -d \
  --name dns-proxy \
  --restart always \
  --network host \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/certs:/app/certs \
  weijiaqaq/dns_automatic_traffic_splitting:latest
```

**Docker Compose：**

```yaml
version: '3'
services:
  dns:
    image: weijiaqaq/dns_automatic_traffic_splitting:latest
    container_name: dns-proxy
    restart: always
    network_mode: "host"
    volumes:
      - ./config:/app/config
      - ./certs:/app/certs
```

> **提示：** 建议使用 `--network host` 以获得最佳 UDP 性能。将 `config.yaml`、`hosts.txt`、`rule.txt` 放入 `config/` 目录。

### 手动安装

1. 从 [Releases](https://github.com/Hamster-Prime/DNS_automatic_traffic_splitting/releases) 下载对应架构的二进制文件
2. 准备 `config.yaml`（参考下方配置说明）
3. 运行：

```bash
chmod +x doh-autoproxy-linux-amd64
./doh-autoproxy-linux-amd64
```

首次运行会自动下载 GeoIP/GeoSite 数据文件。

---

## 配置详解

### 完整配置参考 (`config.yaml`)

```yaml
# ═══════════════════════════════════════════════════════
#  服务监听
# ═══════════════════════════════════════════════════════
listen:
  dns_udp: "53"           # 标准 DNS (UDP)
  dns_tcp: "53"           # 标准 DNS (TCP)
  doh: "443"              # DNS over HTTPS
  doh_path: "/dns-query"  # DoH 路径，默认 /dns-query
  dot: "853"              # DNS over TLS
  doq: "853"              # DNS over QUIC

# ═══════════════════════════════════════════════════════
#  TLS 证书
# ═══════════════════════════════════════════════════════

# 方式一：自动证书 (Let's Encrypt)
# 需要公网 80/443 端口可访问
auto_cert:
  enabled: false
  email: "your-email@example.com"
  domains:
    - "dns.example.com"
  cert_dir: "certs"

# 方式二：手动证书（支持多证书）
# auto_cert 关闭时生效，留空则尝试加载默认 server.crt/server.key
tls_certificates:
  - cert_file: "certs/example.com.crt"
    key_file: "certs/example.com.key"
  - cert_file: "certs/192.168.1.100.crt"    # 支持 IP 证书
    key_file: "certs/192.168.1.100.key"

# ═══════════════════════════════════════════════════════
#  Bootstrap DNS
# ═══════════════════════════════════════════════════════
# 用于解析上游服务器的域名（如 dns.google → IP）
# 内置缓存（5 分钟 TTL）和多服务器重试机制
bootstrap_dns:
  - "223.5.5.5:53"        # 阿里 DNS
  - "8.8.8.8:53"          # Google DNS

# ═══════════════════════════════════════════════════════
#  上游服务器
# ═══════════════════════════════════════════════════════
# 地址支持简写，系统自动补全协议前缀和端口
#   UDP:  223.5.5.5       → 223.5.5.5:53
#   DoT:  223.6.6.6       → tls://223.6.6.6:853
#   DoH:  dns.google      → https://dns.google/dns-query
#   DoQ:  dns.nextdns.io  → quic://dns.nextdns.io:853

upstreams:
  # ── 国内上游 ──
  cn:
    - address: "223.5.5.5"
      protocol: "udp"
      ecs_ip: "114.114.114.114"       # ECS：让 CDN 返回国内最优节点

    - address: "223.6.6.6"
      protocol: "dot"
      ecs_ip: "114.114.114.114"
      pipeline: true                   # 开启连接复用
      insecure_skip_verify: false

  # ── 海外上游 ──
  overseas:
    - address: "1.1.1.1"
      protocol: "doh"
      ecs_ip: "8.8.8.8"
      http3: true                      # 启用 HTTP/3 (QUIC)
      insecure_skip_verify: false

    - address: "8.8.8.8"
      protocol: "dot"
      ecs_ip: "8.8.8.8"
      pipeline: true

    - address: "dns.nextdns.io"
      protocol: "doq"
      ecs_ip: "8.8.8.8"

# ═══════════════════════════════════════════════════════
#  GeoIP / GeoSite 数据
# ═══════════════════════════════════════════════════════
geo_data:
  geoip_dat: "GeoIP.dat"
  geosite_dat: "GeoSite.dat"
  geoip_download_url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite_download_url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"

# ═══════════════════════════════════════════════════════
#  Web 管理面板
# ═══════════════════════════════════════════════════════
web_ui:
  enabled: true
  address: ":8080"
  username: "admin"        # 留空 = 无鉴权（所有人完全控制）
  password: "your-pass"    # 设置后未登录用户进入游客模式（只读）
  # cert_file: ""          # 可选：WebUI 独立 TLS
  # key_file: ""

# ═══════════════════════════════════════════════════════
#  查询日志
# ═══════════════════════════════════════════════════════
query_log:
  enabled: true
  max_history: 5000        # 内存中保留的日志条数
  save_to_file: false      # 是否持久化到文件
  file: "query.log"
  max_size_mb: 1           # 日志文件大小上限，超过自动轮转
```

### 上游协议对比

| 协议 | 端口 | 加密 | 特点 |
|:---|:---|:---|:---|
| **UDP** | 53 | 否 | 最快，适合内网/可信环境 |
| **TCP** | 53 | 否 | 支持大包，可靠传输 |
| **DoT** | 853 | TLS | 加密 DNS，支持 Pipelining 连接复用 |
| **DoQ** | 853 | QUIC | 基于 QUIC 的加密 DNS，低延迟 |
| **DoH** | 443 | HTTPS | 伪装为普通 HTTPS 流量，支持 HTTP/2 和 HTTP/3 |

### 自定义 Hosts (`hosts.txt`)

标准 hosts 格式，优先级最高，直接返回指定 IP：

```text
# 自定义内网解析
192.168.1.1    myrouter.lan
192.168.1.100  nas.home

# 广告屏蔽
0.0.0.0        ads.badsite.com
0.0.0.0        tracker.example.com
```

### 自定义分流规则 (`rule.txt`)

手动指定域名走国内或海外 DNS，优先级高于 GeoSite 自动判断：

```text
# 格式：域名 策略(cn/overseas)
google.com      overseas
github.com      overseas
baidu.com       cn
taobao.com      cn

# 支持正则表达式（以 regexp: 开头）
regexp:.*\.google\..*    overseas
regexp:.*\.aliyun\..*    cn
```

---

## 分流策略详解

查询到达时，按以下优先级依次匹配：

```
┌─────────────────────────────────────────────────────────┐
│  1. Hosts 匹配        → 直接返回自定义 IP               │
│  2. Rule 精确匹配     → 按规则走 CN / Overseas          │
│  3. Rule 正则匹配     → 按规则走 CN / Overseas          │
│  4. GeoSite 匹配      → CN 域名走国内，其他走海外        │
│  5. 双路并发查询       → 同时查国内+海外 DNS             │
│     ├─ 海外成功 + IP 是国内 → 采用国内 DNS 结果          │
│     ├─ 海外成功 + IP 是海外 → 采用海外 DNS 结果          │
│     ├─ 海外失败           → 自动使用国内 DNS 结果        │
│     └─ 全部失败           → 返回错误                    │
└─────────────────────────────────────────────────────────┘
```

**第 5 步的双路并发策略**是核心创新：对于 GeoSite 未收录的域名，不再盲目只查海外 DNS，而是同时向国内和海外发起查询，根据返回的 IP 地理位置智能选择最优结果。这确保了即使是冷门国内域名也能正确解析。

---

## Web 管理面板

访问 `http://your-server:8080` 进入管理面板。

### 功能概览

- **仪表盘** — 实时查询统计（CN/海外分布）、内存/Goroutine 监控、活跃客户端 TOP5、热点域名 TOP5
- **实时日志** — 分页加载、全字段排序、全文搜索，支持文件大小自动轮转
- **可视化配置** — 上游服务器拖拽排序、一键连通性测试（显示协议类型）、监听端口管理
- **安全鉴权** — 用户名/密码保护，未登录用户自动进入只读游客模式
- **个性化** — Liquid Glass 拟态风格 UI，深色/浅色模式切换，完美适配移动端

---

## 架构概览

```
                    ┌──────────────────────────────┐
                    │         客户端请求            │
                    │  UDP / TCP / DoT / DoQ / DoH │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │        DNS Server Layer       │
                    │  DNSServer / DoTServer /      │
                    │  DoQServer / DoHServer        │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │          Router               │
                    │  Hosts → Rules → GeoSite →   │
                    │  双路并发 + GeoIP 验证         │
                    └───────┬──────────┬───────────┘
                            │          │
               ┌────────────▼──┐  ┌────▼────────────┐
               │  CN Upstreams │  │ Overseas Upstreams│
               │  (RaceResolve)│  │  (RaceResolve)   │
               └───────────────┘  └──────────────────┘
                            │          │
                    ┌───────▼──────────▼───────────┐
                    │      Bootstrap Resolver       │
                    │  缓存 + 多服务器重试           │
                    └──────────────────────────────┘
```

---

## 构建

```bash
# 克隆仓库
git clone https://github.com/Hamster-Prime/DNS_automatic_traffic_splitting.git
cd DNS_automatic_traffic_splitting

# 编译
go build -o doh-autoproxy cmd/doh-autoproxy/main.go

# 或使用 Docker 构建
docker build -t dns-proxy .
```

**构建要求：** Go 1.24+

**支持平台：**

| OS | 架构 |
|:---|:---|
| Linux | amd64, arm64, 386 |
| Windows | amd64 |

---

## 端口说明

| 端口 | 协议 | 用途 |
|:---|:---|:---|
| 53 | UDP/TCP | 标准 DNS |
| 853 | TCP | DNS over TLS (DoT) |
| 853 | UDP | DNS over QUIC (DoQ) |
| 443 | TCP/UDP | DNS over HTTPS (DoH, HTTP/2 + HTTP/3) |
| 8080 | TCP | Web 管理面板 |

---

## 常见问题

<details>
<summary><b>系统 DNS 指向本服务后，部分域名解析失败？</b></summary>

确保 `bootstrap_dns` 配置了可直达的 IP 地址（如 `223.5.5.5:53`、`8.8.8.8:53`）。Bootstrap DNS 用于解析上游服务器的域名，必须是 IP 地址而非域名，否则会产生循环依赖。
</details>

<details>
<summary><b>某些国内服务（如阿里云）解析异常？</b></summary>

GeoSite 数据库可能未收录该域名。本服务对未收录域名采用双路并发策略（同时查国内和海外 DNS），会根据返回 IP 的地理位置自动选择最优结果。如果仍有问题，可在 `rule.txt` 中手动添加规则：

```text
alidns.com cn
```
</details>

<details>
<summary><b>如何验证分流是否正确？</b></summary>

打开 Web 管理面板的实时日志页面，查看每条查询的 `Upstream` 字段，会显示具体的分流路径（如 `GeoSite(CN)`、`GeoIP(Overseas)`、`Rule(CN)` 等）。
</details>

<details>
<summary><b>DoH HTTP/3 不工作？</b></summary>

确保上游服务器支持 HTTP/3，且本机 UDP 443 端口未被防火墙拦截。HTTP/3 基于 QUIC (UDP)，部分网络环境可能屏蔽 UDP 443。
</details>

---

## License

本项目采用 [MIT 许可协议](LICENSE)。
