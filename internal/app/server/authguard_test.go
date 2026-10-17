package server

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"voxTun/internal/app/common/util"
)

// TestMain 测试环境没有初始化全局日志，用 Nop logger 填充避免 nil panic
func TestMain(m *testing.M) {
	util.Logger = zap.NewNop().Sugar()
	os.Exit(m.Run())
}

type banRecord struct {
	host string
	ttl  time.Duration
}

func newTestGuard() (*authGuard, *[]banRecord) {
	var bans []banRecord
	g := newAuthGuard(func(host string, ttl time.Duration) {
		bans = append(bans, banRecord{host: host, ttl: ttl})
	})
	return g, &bans
}

func TestAuthGuardBanAtThreshold(t *testing.T) {
	g, bans := newTestGuard()

	for i := 0; i < authFailThreshold-1; i++ {
		g.ReportFailure("1.2.3.4")
	}
	if len(*bans) != 0 {
		t.Fatalf("失败 %d 次不应触发拉黑", authFailThreshold-1)
	}

	g.ReportFailure("1.2.3.4")
	if len(*bans) != 1 {
		t.Fatalf("连续失败 %d 次应触发一次拉黑", authFailThreshold)
	}
	if (*bans)[0].host != "1.2.3.4" || (*bans)[0].ttl != authBanTTL {
		t.Fatalf("拉黑参数异常: %+v", (*bans)[0])
	}

	// 计数已在拉黑时清零：再失败 threshold-1 次不应再次拉黑
	for i := 0; i < authFailThreshold-1; i++ {
		g.ReportFailure("1.2.3.4")
	}
	if len(*bans) != 1 {
		t.Fatal("拉黑后计数应清零，未满阈值不应再次拉黑")
	}
}

func TestAuthGuardSuccessResets(t *testing.T) {
	g, bans := newTestGuard()

	for i := 0; i < authFailThreshold-1; i++ {
		g.ReportFailure("1.2.3.4")
	}
	g.ReportSuccess("1.2.3.4")
	// 成功清零后需重新累计满阈值才拉黑
	for i := 0; i < authFailThreshold-1; i++ {
		g.ReportFailure("1.2.3.4")
	}
	if len(*bans) != 0 {
		t.Fatal("认证成功应清零失败计数")
	}
}

func TestAuthGuardPerIP(t *testing.T) {
	g, bans := newTestGuard()

	for i := 0; i < authFailThreshold-1; i++ {
		g.ReportFailure("1.1.1.1")
	}
	// 另一个 IP 的失败不应累加到第一个 IP 上
	for i := 0; i < authFailThreshold-1; i++ {
		g.ReportFailure("2.2.2.2")
	}
	if len(*bans) != 0 {
		t.Fatal("失败计数应按 IP 独立累计")
	}
}
