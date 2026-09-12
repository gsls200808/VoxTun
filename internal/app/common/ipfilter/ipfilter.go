package ipfilter

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"voxTun/internal/app/common/config"
	"voxTun/internal/app/common/util"
)

const (
	// denyLogInterval 同一 IP 的拒绝日志最小间隔，避免扫描流量刷屏
	denyLogInterval = 5 * time.Minute
	// denyLogMaxEntries 拒绝日志去重表的最大条目数，超出时清理过期项
	denyLogMaxEntries = 1024
)

// Filter IP 黑白名单过滤器
type Filter struct {
	mu      sync.RWMutex // 保护以下三个字段，使名单支持运行期热更新
	enabled bool
	allow   []*net.IPNet // 白名单，非空时仅放行其中的地址
	deny    []*net.IPNet // 黑名单，优先级高于白名单

	logMu  sync.Mutex
	denied map[string]time.Time // IP -> 上次记录拒绝日志的时间
}

// New 根据配置构建过滤器
func New(cfg config.IPFilterConfig) (*Filter, error) {
	f := &Filter{enabled: cfg.Enable, denied: make(map[string]time.Time)}
	var err error
	if f.allow, err = parseList(cfg.AllowList); err != nil {
		return nil, fmt.Errorf("allowList: %w", err)
	}
	if f.deny, err = parseList(cfg.DenyList); err != nil {
		return nil, fmt.Errorf("denyList: %w", err)
	}
	return f, nil
}

// Validate 只校验名单格式，不构建过滤器
func Validate(cfg config.IPFilterConfig) error {
	if _, err := parseList(cfg.AllowList); err != nil {
		return fmt.Errorf("allowList: %w", err)
	}
	if _, err := parseList(cfg.DenyList); err != nil {
		return fmt.Errorf("denyList: %w", err)
	}
	return nil
}

// Reload 用新配置替换名单内容（运行期热更新）。
// 解析失败时直接返回错误，原有名单保持不变。
func (f *Filter) Reload(cfg config.IPFilterConfig) error {
	allow, err := parseList(cfg.AllowList)
	if err != nil {
		return fmt.Errorf("allowList: %w", err)
	}
	deny, err := parseList(cfg.DenyList)
	if err != nil {
		return fmt.Errorf("denyList: %w", err)
	}
	f.mu.Lock()
	f.enabled, f.allow, f.deny = cfg.Enable, allow, deny
	f.mu.Unlock()
	return nil
}

// parseList 解析 IP / CIDR 列表，单个 IP 会转换为 /32 或 /128
func parseList(items []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(item); err == nil {
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(item)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip or cidr %q", item)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

func contains(list []*net.IPNet, ip net.IP) bool {
	for _, n := range list {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// match 返回命中的第一条规则（CIDR 文本形式），未命中返回空串
func match(list []*net.IPNet, ip net.IP) string {
	for _, n := range list {
		if n.Contains(ip) {
			return n.String()
		}
	}
	return ""
}

// Enabled 是否启用过滤
func (f *Filter) Enabled() bool {
	if f == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enabled
}

// Allow 判断 IP 是否放行：黑名单优先，白名单非空时仅放行白名单内的地址
func (f *Filter) Allow(ip net.IP) bool {
	if f == nil {
		return true
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.enabled {
		return true
	}
	if ip == nil {
		return false
	}
	if contains(f.deny, ip) {
		return false
	}
	if len(f.allow) > 0 {
		return contains(f.allow, ip)
	}
	return true
}

// CheckResult IP 检测结果，用于面板展示「该 IP 在当前配置下会不会被拦截」
type CheckResult struct {
	Enabled bool   `json:"enabled"` // 过滤是否启用
	Allowed bool   `json:"allowed"` // 是否放行
	Rule    string `json:"rule"`    // 命中的规则（CIDR 文本），空表示未命中任何规则
	Source  string `json:"source"`  // deny / allow / default
}

// Check 按当前名单判定指定 IP，并给出命中的具体规则（语义与 Allow 完全一致）
func (f *Filter) Check(ip net.IP) CheckResult {
	f.mu.RLock()
	defer f.mu.RUnlock()

	res := CheckResult{Enabled: f.enabled}
	if !f.enabled {
		res.Allowed = true
		res.Source = "default"
		return res
	}
	if ip == nil {
		res.Source = "default"
		return res
	}
	if rule := match(f.deny, ip); rule != "" {
		res.Rule, res.Source = rule, "deny"
		return res
	}
	if len(f.allow) > 0 {
		if rule := match(f.allow, ip); rule != "" {
			res.Allowed, res.Rule, res.Source = true, rule, "allow"
			return res
		}
		// 白名单非空且未命中任何白名单规则：拦截
		res.Source = "default"
		return res
	}
	res.Allowed = true
	res.Source = "default"
	return res
}

// AllowAddr 判断 host:port 形式的对端地址是否放行
func (f *Filter) AllowAddr(addr net.Addr) bool {
	if !f.Enabled() {
		return true
	}
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	return f.Allow(net.ParseIP(host))
}

// AllowAddrLogged 与 AllowAddr 相同，但被拒绝时会记录 INFO 日志，
// 便于发现对端 IP 漂移后及时补充白名单。同一 IP 在 denyLogInterval 内只记录一次。
// scope 用于标识被拒流量属于哪个入口，如 "control"、"udp proxy sip-udp:5060"。
func (f *Filter) AllowAddrLogged(addr net.Addr, scope string) bool {
	if f.AllowAddr(addr) {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	if !f.shouldLog(host) {
		return false
	}
	util.Logger.Infow("ip rejected by filter", "client", addr.String(), "scope", scope)
	return false
}

// shouldLog 判断该 IP 的拒绝日志是否应当输出，并按需清理过期记录
func (f *Filter) shouldLog(host string) bool {
	now := time.Now()
	f.logMu.Lock()
	defer f.logMu.Unlock()
	if last, ok := f.denied[host]; ok && now.Sub(last) < denyLogInterval {
		return false
	}
	if len(f.denied) >= denyLogMaxEntries {
		for ip, t := range f.denied {
			if now.Sub(t) >= denyLogInterval {
				delete(f.denied, ip)
			}
		}
	}
	f.denied[host] = now
	return true
}
