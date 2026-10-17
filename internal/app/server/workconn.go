package server

import (
	"net"
	"sync"

	"voxTun/internal/app/common/consts"
	"voxTun/internal/app/common/protocol"
	"voxTun/internal/app/common/util"
)

// workConnWaiter 等待 work 连接
type workConnWaiter struct {
	ch  chan net.Conn
}

// Server 上的 work 连接管理
type workConnManager struct {
	mu      sync.Mutex
	waiters map[string][]*workConnWaiter // proxyName -> 等待队列
}

func newWorkConnManager() *workConnManager {
	return &workConnManager{waiters: make(map[string][]*workConnWaiter)}
}

// waitWorkConn 等待某个代理的 work 连接
func (s *Server) waitWorkConn(proxyName string) net.Conn {
	w := &workConnWaiter{ch: make(chan net.Conn, 1)}
	s.workMgr.mu.Lock()
	s.workMgr.waiters[proxyName] = append(s.workMgr.waiters[proxyName], w)
	s.workMgr.mu.Unlock()
	conn := <-w.ch
	return conn
}

// deliverWorkConn 交付 work 连接给等待者
func (s *Server) deliverWorkConn(proxyName string, conn net.Conn) bool {
	s.workMgr.mu.Lock()
	defer s.workMgr.mu.Unlock()
	waiters := s.workMgr.waiters[proxyName]
	if len(waiters) == 0 {
		return false
	}
	w := waiters[0]
	s.workMgr.waiters[proxyName] = waiters[1:]
	w.ch <- conn
	return true
}

// handleWorkConn 处理一个 work 连接（客户端发起，先发 StartWorkConn）
func (s *Server) handleWorkConn(conn net.Conn, firstPayload []byte) {
	var req protocol.StartWorkConn
	if err := protocol.Decode(firstPayload, &req); err != nil {
		util.Logger.Errorw("decode StartWorkConn", "err", err)
		_ = conn.Close()
		return
	}
	if ok := s.deliverWorkConn(req.ProxyName, conn); !ok {
		util.Logger.Warnw("no waiter for work conn", "proxy", req.ProxyName)
		_ = conn.Close()
	}
}

// handleIncomingConn 处理新到的连接，判断是控制连接还是 work 连接
func (s *Server) handleIncomingConn(conn net.Conn) {
	// 黑名单过滤（静态 denyList + 认证防爆动态拉黑）。
	// 控制/工作连接不再依赖白名单：voxcli 出口 IP 可能频繁变化，白名单来不及更新。
	// 入口安全由 token 认证（handleControlConn）+ authGuard 防爆保证，与 frp 官方模型一致。
	// 白名单仍在数据面入口（tcp/udp proxy、rtp relay）生效。
	if s.ipFilter.DeniedAddrLogged(conn.RemoteAddr(), "control") {
		_ = conn.Close()
		return
	}
	util.SetKeepAlive(conn)
	// 读取第一条消息判断类型
	msgType, payload, err := protocol.ReadMsg(conn)
	if err != nil {
		util.Logger.Errorw("read first msg", "err", err)
		_ = conn.Close()
		return
	}
	switch msgType {
	case consts.TypeAuth:
		// 控制连接：把已读的 Auth 消息重新喂给 handleClient 处理
		// 这里通过包装 conn 回放，简化处理：直接处理认证
		s.handleControlConn(conn, payload)
	case consts.TypeStartWorkConn:
		s.handleWorkConn(conn, payload)
	default:
		util.Logger.Warnw("unexpected first msg type", "type", msgType)
		_ = conn.Close()
	}
}

// handleControlConn 处理控制连接（首条消息为 Auth，已经在 payload 中）
func (s *Server) handleControlConn(conn net.Conn, authPayload []byte) {
	remoteAddr := conn.RemoteAddr().String()
	util.Logger.Infow("client connected", "addr", remoteAddr)

	session := NewClientSession(conn, s)
	s.addClient(session)
	defer func() {
		s.removeClient(session)
		session.Close()
	}()

	if err := session.HandleAuthPayload(s.cfg.Token, authPayload); err != nil {
		util.Logger.Warnw("client auth failed", "addr", remoteAddr, "err", err)
		s.authGuard.ReportFailure(remoteHost(remoteAddr))
		return
	}
	s.authGuard.ReportSuccess(remoteHost(remoteAddr))
	util.Logger.Infow("client authenticated", "addr", remoteAddr)

	go session.heartbeat()
	session.Run()
}

// remoteHost 从 host:port 形式的对端地址提取 IP 部分，解析失败时原样返回
func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
