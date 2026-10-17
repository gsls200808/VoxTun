package server

import (
	"sync"
	"time"

	"voxTun/internal/app/common/util"
)

const (
	// authFailThreshold 同一 IP 连续认证失败达到该次数后触发动态拉黑
	authFailThreshold = 5
	// authBanTTL 动态拉黑时长，过期自动解除
	authBanTTL = time.Hour
	// authFailMaxEntries 失败计数表上限，超出时整体清零（牺牲少量计数精度换取内存有界）
	authFailMaxEntries = 4096
)

// authGuard 控制连接认证防爆守卫：同一 IP 连续 token 认证失败达到阈值后，
// 通过动态拉黑（只存在内存，不写配置文件）封禁该 IP 一段时间；认证成功则清零计数。
// 控制/工作连接入口放开白名单后，token 是控制面唯一凭证，本机制防止在线爆破。
type authGuard struct {
	mu       sync.Mutex
	failures map[string]int
	ban      func(host string, ttl time.Duration) // 通常为 ipFilter.DenyDynamic
}

func newAuthGuard(ban func(string, time.Duration)) *authGuard {
	return &authGuard{failures: make(map[string]int), ban: ban}
}

// ReportFailure 记录一次认证失败；达到阈值时拉黑来源 IP 并清零其计数。
func (g *authGuard) ReportFailure(host string) {
	g.mu.Lock()
	if len(g.failures) >= authFailMaxEntries {
		g.failures = make(map[string]int)
	}
	g.failures[host]++
	n := g.failures[host]
	if n >= authFailThreshold {
		delete(g.failures, host)
	}
	g.mu.Unlock()

	if n >= authFailThreshold {
		util.Logger.Warnw("too many auth failures, banning ip",
			"client", host, "failures", n, "ttl", authBanTTL.String())
		g.ban(host, authBanTTL)
	}
}

// ReportSuccess 认证成功后清零该 IP 的失败计数。
func (g *authGuard) ReportSuccess(host string) {
	g.mu.Lock()
	delete(g.failures, host)
	g.mu.Unlock()
}
