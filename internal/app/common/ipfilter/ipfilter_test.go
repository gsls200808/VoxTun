package ipfilter

import (
	"net"
	"testing"
	"time"

	"voxTun/internal/app/common/config"
)

func newTestFilter(t *testing.T, cfg config.IPFilterConfig) *Filter {
	t.Helper()
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func TestDeniedStaticList(t *testing.T) {
	f := newTestFilter(t, config.IPFilterConfig{
		Enable:    true,
		AllowList: []string{"10.0.0.0/8"},
		DenyList:  []string{"1.2.3.4"},
	})

	if !f.Denied(net.ParseIP("1.2.3.4")) {
		t.Fatal("静态黑名单 IP 应被 Denied 命中")
	}
	// Denied 与白名单无关：不在白名单内的 IP 也不应被 Denied 命中
	if f.Denied(net.ParseIP("9.9.9.9")) {
		t.Fatal("未命中黑名单的 IP 不应被 Denied 命中，即使它不在白名单内")
	}
	// 但 Allow 仍受白名单约束
	if f.Allow(net.ParseIP("9.9.9.9")) {
		t.Fatal("白名单非空时，不在白名单内的 IP 不应被 Allow 放行")
	}
}

func TestDenyDynamic(t *testing.T) {
	f := newTestFilter(t, config.IPFilterConfig{Enable: true, AllowList: []string{"0.0.0.0/0"}})
	ip := net.ParseIP("5.6.7.8")

	f.DenyDynamic("5.6.7.8", time.Hour)
	if !f.Denied(ip) {
		t.Fatal("动态拉黑后 Denied 应命中")
	}
	if f.Allow(ip) {
		t.Fatal("动态拉黑后 Allow 应拒绝")
	}
	res := f.Check(ip)
	if res.Allowed || res.Source != "deny" || res.Rule != "dynamic-ban" {
		t.Fatalf("Check 应反映动态拉黑: %+v", res)
	}
}

func TestDenyDynamicExpiry(t *testing.T) {
	f := newTestFilter(t, config.IPFilterConfig{Enable: true})
	ip := net.ParseIP("5.6.7.9")

	f.DenyDynamic("5.6.7.9", 30*time.Millisecond)
	if !f.Denied(ip) {
		t.Fatal("动态拉黑后 Denied 应命中")
	}
	time.Sleep(60 * time.Millisecond)
	if f.Denied(ip) {
		t.Fatal("动态拉黑过期后 Denied 不应命中")
	}
	if !f.Allow(ip) {
		t.Fatal("动态拉黑过期后 Allow 应放行（无白名单约束）")
	}
}

func TestDeniedDisabled(t *testing.T) {
	f := newTestFilter(t, config.IPFilterConfig{Enable: false, DenyList: []string{"1.2.3.4"}})
	f.DenyDynamic("5.6.7.8", time.Hour)

	if f.Denied(net.ParseIP("1.2.3.4")) || f.Denied(net.ParseIP("5.6.7.8")) {
		t.Fatal("过滤器未启用时 Denied 应一律为 false")
	}
}
