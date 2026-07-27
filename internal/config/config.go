package config

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// saveMu 串行化配置落盘：config.yaml / hosts.txt / rule.txt 三个文件
// 必须作为一个整体写入，否则并发保存会产生互相矛盾的组合。
var saveMu sync.Mutex

type Config struct {
	Listen          ListenConfig      `yaml:"listen" json:"listen"`
	BootstrapDNS    []string          `yaml:"bootstrap_dns" json:"bootstrap_dns"`
	Upstreams       UpstreamsConfig   `yaml:"upstreams" json:"upstreams"`
	Hosts           map[string]string `yaml:"-" json:"hosts"`
	Rules           map[string]string `yaml:"-" json:"rules"`
	GeoData         GeoDataConfig     `yaml:"geo_data" json:"geo_data"`
	AutoCert        AutoCertConfig    `yaml:"auto_cert" json:"auto_cert"`
	TLSCertificates []TLSCertConfig   `yaml:"tls_certificates" json:"tls_certificates"`
	WebUI           WebUIConfig       `yaml:"web_ui" json:"web_ui"`
	QueryLog        QueryLogConfig    `yaml:"query_log" json:"query_log"`
	ConfigDir       string            `yaml:"-" json:"-"`
}

type TLSCertConfig struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

type QueryLogConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	MaxHistory int    `yaml:"max_history" json:"max_history"`
	File       string `yaml:"file" json:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb" json:"max_size_mb"`
	SaveToFile bool   `yaml:"save_to_file" json:"save_to_file"`
}

type WebUIConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Address   string `yaml:"address" json:"address"`
	Username  string `yaml:"username" json:"username"`
	Password  string `yaml:"password" json:"password"`
	CertFile  string `yaml:"cert_file" json:"cert_file"`
	KeyFile   string `yaml:"key_file" json:"key_file"`
	GuestMode bool   `yaml:"guest_mode" json:"guest_mode"`
}

type AutoCertConfig struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Email   string   `yaml:"email" json:"email"`
	Domains []string `yaml:"domains" json:"domains"`
	CertDir string   `yaml:"cert_dir" json:"cert_dir"`
}

type ListenConfig struct {
	Address string `yaml:"address" json:"address"`
	DNSUDP  string `yaml:"dns_udp" json:"dns_udp"`
	DNSTCP  string `yaml:"dns_tcp" json:"dns_tcp"`
	DOH     string `yaml:"doh" json:"doh"`
	DoHPath string `yaml:"doh_path" json:"doh_path"`
	DOT     string `yaml:"dot" json:"dot"`
	DOQ     string `yaml:"doq" json:"doq"`
}

func (l ListenConfig) DNSUDPAddr() string {
	return resolveListenAddr(l.Address, l.DNSUDP)
}

func (l ListenConfig) DNSTCPAddr() string {
	return resolveListenAddr(l.Address, l.DNSTCP)
}

func (l ListenConfig) DOHAddr() string {
	return resolveListenAddr(l.Address, l.DOH)
}

func (l ListenConfig) DOTAddr() string {
	return resolveListenAddr(l.Address, l.DOT)
}

func (l ListenConfig) DOQAddr() string {
	return resolveListenAddr(l.Address, l.DOQ)
}

type UpstreamsConfig struct {
	CN       []UpstreamServer `yaml:"cn" json:"cn"`
	Overseas []UpstreamServer `yaml:"overseas" json:"overseas"`
}

type UpstreamServer struct {
	Address            string `yaml:"address" json:"address"`
	Protocol           string `yaml:"protocol" json:"protocol"`
	ECSIP              string `yaml:"ecs_ip" json:"ecs_ip"`
	EnablePipeline     bool   `yaml:"pipeline" json:"pipeline"`
	EnableH3           bool   `yaml:"http3" json:"http3"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

type GeoDataConfig struct {
	GeoIPDat           string `yaml:"geoip_dat" json:"geoip_dat"`
	GeoSiteDat         string `yaml:"geosite_dat" json:"geosite_dat"`
	GeoIPDownloadURL   string `yaml:"geoip_download_url" json:"geoip_download_url"`
	GeoSiteDownloadURL string `yaml:"geosite_download_url" json:"geosite_download_url"`
	AutoUpdate         string `yaml:"auto_update" json:"auto_update"`
}

func LoadConfig(configPath string) (*Config, error) {
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config path: %w", err)
	}
	configDir := filepath.Dir(absPath)

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("无法读取配置文件 %s: %w", absPath, err)
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("无法解析配置文件 %s: %w", absPath, err)
	}

	cfg.ConfigDir = configDir

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to inspect config defaults in %s: %w", absPath, err)
	}

	if !hasNestedKey(raw, "query_log", "enabled") {
		cfg.QueryLog.Enabled = true
	}
	if cfg.QueryLog.MaxHistory <= 0 {
		cfg.QueryLog.MaxHistory = 5000
	}

	normalizeListenConfig(&cfg.Listen)

	cfg.Hosts = make(map[string]string)
	cfg.Rules = make(map[string]string)

	hostsPath := filepath.Join(configDir, "hosts.txt")
	if err := loadHostsFile(hostsPath, cfg.Hosts); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("加载 hosts.txt 失败: %w", err)
		}
	}

	rulesPath := filepath.Join(configDir, "rule.txt")
	if err := loadRulesFile(rulesPath, cfg.Rules); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("加载 rule.txt 失败: %w", err)
		}
	}

	resolvePath := func(p string) string {
		if p == "" {
			return ""
		}
		if !filepath.IsAbs(p) {
			return filepath.Join(configDir, p)
		}
		return p
	}

	if cfg.GeoData.GeoIPDat == "" {
		cfg.GeoData.GeoIPDat = "geoip.dat"
	}
	cfg.GeoData.GeoIPDat = resolvePath(cfg.GeoData.GeoIPDat)

	if cfg.GeoData.GeoSiteDat == "" {
		cfg.GeoData.GeoSiteDat = "geosite.dat"
	}
	cfg.GeoData.GeoSiteDat = resolvePath(cfg.GeoData.GeoSiteDat)

	return &cfg, nil
}

func hasNestedKey(root map[string]interface{}, keys ...string) bool {
	current := root
	for i, key := range keys {
		value, ok := current[key]
		if !ok {
			return false
		}
		if i == len(keys)-1 {
			return true
		}
		next, ok := value.(map[string]interface{})
		if !ok {
			return false
		}
		current = next
	}
	return false
}

func (c *Config) Save(configPath string) error {
	saveMu.Lock()
	defer saveMu.Unlock()

	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	configDir := filepath.Dir(absPath)
	c.ConfigDir = configDir

	normalizeListenConfig(&c.Listen)

	relPath := func(p string) string {
		if strings.HasPrefix(p, configDir) {
			if rel, err := filepath.Rel(configDir, p); err == nil {
				return rel
			}
		}
		return p
	}

	saveCfg := *c
	saveCfg.GeoData.GeoIPDat = relPath(c.GeoData.GeoIPDat)
	saveCfg.GeoData.GeoSiteDat = relPath(c.GeoData.GeoSiteDat)

	data, err := yaml.Marshal(saveCfg)
	if err != nil {
		return fmt.Errorf("无法序列化配置: %w", err)
	}
	// 配置内含 WebUI 明文密码，使用 0600 而非 0644。
	if err := writeFileAtomic(absPath, data, 0600); err != nil {
		return fmt.Errorf("无法写入配置文件 %s: %w", absPath, err)
	}

	hostsPath := filepath.Join(configDir, "hosts.txt")
	if err := saveHostsFile(hostsPath, c.Hosts); err != nil {
		return fmt.Errorf("无法写入 hosts.txt: %w", err)
	}

	rulesPath := filepath.Join(configDir, "rule.txt")
	if err := saveRulesFile(rulesPath, c.Rules); err != nil {
		return fmt.Errorf("无法写入 rule.txt: %w", err)
	}

	return nil
}

// writeFileAtomic 先写临时文件再 rename，避免"截断后写入失败"
// 导致配置文件被清空——旧实现的 os.Create/WriteFile 在磁盘写满或
// 进程被杀时会留下空文件甚至半截配置。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // rename 成功后此调用无副作用
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// marshalPairs 以域名排序输出 "key value" 行，保证同样的内容
// 每次生成一致的文件（Go 的 map 遍历顺序随机，旧实现会让
// hosts.txt/rule.txt 每次保存都产生无意义的全文件 diff）。
func marshalPairs(m map[string]string, line func(k, v string) string) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	// 预估每行长度，减少扩容次数。
	buf.Grow(len(keys) * 48)
	for _, k := range keys {
		buf.WriteString(line(k, m[k]))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func saveHostsFile(path string, hosts map[string]string) error {
	data := marshalPairs(hosts, func(domain, ip string) string {
		return ip + " " + domain
	})
	return writeFileAtomic(path, data, 0644)
}

func saveRulesFile(path string, rules map[string]string) error {
	data := marshalPairs(rules, func(domain, target string) string {
		return domain + " " + target
	})
	return writeFileAtomic(path, data, 0644)
}

func loadHostsFile(path string, hosts map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ip := parts[0]
			for _, domain := range parts[1:] {
				hosts[strings.ToLower(domain)] = ip
			}
		}
	}
	return scanner.Err()
}

func loadRulesFile(path string, rules map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			domain := strings.ToLower(parts[0])
			target := strings.ToLower(parts[1])
			rules[domain] = target
		}
	}
	return scanner.Err()
}

func GetDefaultConfigPath() string {
	if p := os.Getenv("DOH_AUTOPROXY_CONFIG"); p != "" {
		return p
	}

	possiblePaths := []string{
		"config.yaml",
		"config/config.yaml",
		"/app/config/config.yaml",
		"/etc/doh-autoproxy/config.yaml",
	}

	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "config.yaml"
}

func normalizeListenConfig(listen *ListenConfig) {
	if listen == nil {
		return
	}

	listen.Address = strings.TrimSpace(listen.Address)
	inferredAddress := ""

	normalizePort := func(p *string) {
		host, port := splitListenValue(*p)
		if port != "" {
			*p = port
		} else {
			*p = strings.TrimSpace(*p)
		}
		if listen.Address == "" && inferredAddress == "" && host != "" {
			inferredAddress = host
		}
	}

	normalizePort(&listen.DNSUDP)
	normalizePort(&listen.DNSTCP)
	normalizePort(&listen.DOH)
	normalizePort(&listen.DOT)
	normalizePort(&listen.DOQ)

	if listen.Address == "" {
		listen.Address = inferredAddress
	}
}

func splitListenValue(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	if strings.HasPrefix(value, ":") {
		return "", strings.TrimSpace(strings.TrimPrefix(value, ":"))
	}
	if !strings.Contains(value, ":") {
		return "", value
	}

	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return strings.TrimSpace(host), strings.TrimSpace(port)
	}

	if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}

	return "", value
}

func resolveListenAddr(address, value string) string {
	_, port := splitListenValue(value)
	if port == "" {
		return ""
	}

	host := strings.TrimSpace(address)
	if host == "" {
		host = "0.0.0.0"
	}

	return net.JoinHostPort(host, port)
}
