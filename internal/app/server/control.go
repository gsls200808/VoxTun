package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"voxTun/internal/app/common/consts"
	"voxTun/internal/app/common/protocol"
	"voxTun/internal/app/common/util"
	"voxTun/internal/app/protocol/sip"
)

// ClientSession 服务端维护的客户端控制连接会话
type ClientSession struct {
	conn       net.Conn
	server     *Server
	authed     bool
	startAt    time.Time
	proxies    map[string]*ProxyInfo
	proxiesMu  sync.RWMutex
	sendMu     sync.Mutex
	lastPing   time.Time
	pingMu     sync.Mutex
	closeOnce  sync.Once
	closed     chan struct{}

	// RTP 中继管理：callID#mediaIdx -> *RTPRelay
	rtpRelays   map[string]*RTPRelay
	rtpRelaysMu sync.Mutex
}

// NewClientSession 创建客户端会话
func NewClientSession(conn net.Conn, srv *Server) *ClientSession {
	return &ClientSession{
		conn:      conn,
		server:    srv,
		startAt:   time.Now(),
		proxies:   make(map[string]*ProxyInfo),
		lastPing:  time.Now(),
		closed:    make(chan struct{}),
		rtpRelays: make(map[string]*RTPRelay),
	}
}

// sendMsg 线程安全地发送消息
func (c *ClientSession) sendMsg(msgType byte, payload interface{}) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return protocol.WriteMsg(c.conn, msgType, payload)
}

// HandleAuth 处理客户端认证
func (c *ClientSession) HandleAuth(token string) error {
	msgType, payload, err := protocol.ReadMsg(c.conn)
	if err != nil {
		return fmt.Errorf("read auth: %w", err)
	}
	if msgType != consts.TypeAuth {
		return fmt.Errorf("expected auth, got type %d", msgType)
	}
	return c.HandleAuthPayload(token, payload)
}

// HandleAuthPayload 使用已读取的认证载荷完成认证
func (c *ClientSession) HandleAuthPayload(token string, payload []byte) error {
	var auth protocol.Auth
	if err := protocol.Decode(payload, &auth); err != nil {
		return fmt.Errorf("decode auth: %w", err)
	}
	if token != "" && auth.Token != token {
		_ = c.sendMsg(consts.TypeAuthResp, protocol.AuthResp{OK: false, Error: "invalid token"})
		return fmt.Errorf("invalid token")
	}
	c.authed = true
	return c.sendMsg(consts.TypeAuthResp, protocol.AuthResp{OK: true})
}

// Run 处理控制连接消息循环
func (c *ClientSession) Run() {
	for {
		msgType, payload, err := protocol.ReadMsg(c.conn)
		if err != nil {
			util.Logger.Errorw("read control msg", "addr", c.conn.RemoteAddr().String(), "err", err)
			return
		}
		switch msgType {
		case consts.TypePing:
			c.handlePing(payload)
		case consts.TypeNewProxy:
			c.handleNewProxy(payload)
		case consts.TypeProxyClosed:
			c.handleProxyClosed(payload)
		case consts.TypeUDPPacket:
			c.handleUDPPacketFromClient(payload)
		case consts.TypeNewRTPRelayResp:
			c.handleNewRTPRelayResp(payload)
		case consts.TypeStartWorkConn:
			// 客户端通过新的连接发起 StartWorkConn，不在主循环处理
		default:
			util.Logger.Warnw("unknown msg type", "type", msgType)
		}
	}
}

func (c *ClientSession) handlePing(payload []byte) {
	c.pingMu.Lock()
	c.lastPing = time.Now()
	c.pingMu.Unlock()
	var p protocol.Ping
	_ = protocol.Decode(payload, &p)
	_ = c.sendMsg(consts.TypePong, protocol.Pong{Timestamp: time.Now().Unix()})
}

func (c *ClientSession) handleNewProxy(payload []byte) {
	var req protocol.NewProxy
	if err := protocol.Decode(payload, &req); err != nil {
		util.Logger.Errorw("decode NewProxy", "err", err)
		return
	}
	resp := protocol.NewProxyResp{ProxyName: req.ProxyName}

	if req.ProxyName == "" {
		resp.Error = "proxy name required"
		_ = c.sendMsg(consts.TypeNewProxyResp, resp)
		return
	}
	c.proxiesMu.RLock()
	_, exists := c.proxies[req.ProxyName]
	c.proxiesMu.RUnlock()
	if exists {
		resp.Error = "proxy name already exists"
		_ = c.sendMsg(consts.TypeNewProxyResp, resp)
		return
	}

	proxyType := req.ProxyType
	if proxyType == consts.ProxyTypeSIP {
		proxyType = consts.ProxyTypeUDP // SIP 走 UDP 中继，内部做 SDP 重写
	}
	if proxyType == consts.ProxyTypeIAX {
		proxyType = consts.ProxyTypeUDP
	}
	if proxyType == consts.ProxyTypeSIPTCP || proxyType == consts.ProxyTypeSIPTLS {
		// SIP over TCP / TLS 内部均走 TCP 中继：按 SIP 消息分帧转发，
		// 回程（内网 -> 外部）复用 SDP / 路由头重写与 RTP 中继
		proxyType = consts.ProxyTypeTCP
	}

	p := &ProxyInfo{
		name:        req.ProxyName,
		proxyType:   proxyType,
		origType:    req.ProxyType,
		localIP:     req.LocalIP,
		localPort:   req.LocalPort,
		remotePort:  req.RemotePort,
		rewriteSDP:  req.RewriteSDP,
		client:      c,
		udpPeers:    make(map[string]*udpPeer),
	}

	if err := c.server.RegisterProxy(p); err != nil {
		resp.Error = err.Error()
		_ = c.sendMsg(consts.TypeNewProxyResp, resp)
		return
	}

	if err := p.Start(c.server); err != nil {
		c.server.UnregisterProxy(p.proxyType, p.remotePort)
		resp.Error = err.Error()
		_ = c.sendMsg(consts.TypeNewProxyResp, resp)
		return
	}

	c.proxiesMu.Lock()
	c.proxies[req.ProxyName] = p
	c.proxiesMu.Unlock()

	resp.OK = true
	resp.RemotePort = p.remotePort
	_ = c.sendMsg(consts.TypeNewProxyResp, resp)
	util.Logger.Infow("proxy started", "name", p.name, "type", p.origType, "remotePort", p.remotePort)
}

func (c *ClientSession) handleProxyClosed(payload []byte) {
	var req protocol.ProxyClosed
	if err := protocol.Decode(payload, &req); err != nil {
		return
	}
	c.proxiesMu.Lock()
	if p, ok := c.proxies[req.ProxyName]; ok {
		p.Stop()
		c.server.UnregisterProxy(p.proxyType, p.remotePort)
		delete(c.proxies, req.ProxyName)
	}
	c.proxiesMu.Unlock()
	util.Logger.Infow("proxy closed", "name", req.ProxyName)
}

// handleUDPPacketFromClient 处理客户端回传的 UDP 包，转发给外部对端
// 先判断 ProxyName 是否为 RTP relay，是则路由到 relay，否则路由到普通 proxy
func (c *ClientSession) handleUDPPacketFromClient(payload []byte) {
	var pkt protocol.UDPPacket
	if err := protocol.Decode(payload, &pkt); err != nil {
		util.Logger.Errorw("decode UDPPacket from client", "err", err)
		return
	}
	// 先查 RTP relay
	c.rtpRelaysMu.Lock()
	relay, ok := c.rtpRelays[pkt.ProxyName]
	c.rtpRelaysMu.Unlock()
	if ok {
		relay.SendToPeer(pkt.Data)
		return
	}
	// 否则普通 proxy
	p := c.GetProxy(pkt.ProxyName)
	if p == nil {
		util.Logger.Warnw("UDPPacket for unknown proxy", "name", pkt.ProxyName)
		return
	}
	p.SendUDPPacketToPeer(pkt.RemoteAddr, pkt.Data)
}

// handleNewRTPRelayResp 处理客户端 RTP 中继建立响应
func (c *ClientSession) handleNewRTPRelayResp(payload []byte) {
	var resp protocol.NewRTPRelayResp
	if err := protocol.Decode(payload, &resp); err != nil {
		util.Logger.Errorw("decode NewRTPRelayResp", "err", err)
		return
	}
	if !resp.OK {
		util.Logger.Warnw("rtp relay setup failed on client", "relay", resp.RelayID, "err", resp.Error)
		// 失败时也停止服务端侧 relay（释放端口）
		c.rtpRelaysMu.Lock()
		if relay, ok := c.rtpRelays[resp.RelayID]; ok {
			relay.Stop(false)
			delete(c.rtpRelays, resp.RelayID)
		}
		c.rtpRelaysMu.Unlock()
	} else {
		util.Logger.Infow("rtp relay ready", "relay", resp.RelayID)
	}
}

// RequestWorkConn 请求客户端新建工作连接
func (c *ClientSession) RequestWorkConn(proxyName string) error {
	return c.sendMsg(consts.TypeNewWorkConn, protocol.NewWorkConn{ProxyName: proxyName})
}

// heartbeat 心跳检测
func (c *ClientSession) heartbeat() {
	ticker := time.NewTicker(consts.HeartbeatInterval * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			c.pingMu.Lock()
			last := c.lastPing
			c.pingMu.Unlock()
			if time.Since(last) > consts.HeartbeatTimeout*time.Second {
				util.Logger.Warnw("client heartbeat timeout", "addr", c.conn.RemoteAddr().String())
				c.Close()
				return
			}
		}
	}
}

// Close 关闭客户端会话
func (c *ClientSession) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
		c.proxiesMu.Lock()
		for _, p := range c.proxies {
			p.Stop()
			c.server.UnregisterProxy(p.proxyType, p.remotePort)
		}
		c.proxies = make(map[string]*ProxyInfo)
		c.proxiesMu.Unlock()
		// 关闭所有 RTP relays
		c.rtpRelaysMu.Lock()
		for _, r := range c.rtpRelays {
			r.Stop(false)
		}
		c.rtpRelays = make(map[string]*RTPRelay)
		c.rtpRelaysMu.Unlock()
	})
}

// GetProxy 获取代理
func (c *ClientSession) GetProxy(name string) *ProxyInfo {
	c.proxiesMu.RLock()
	defer c.proxiesMu.RUnlock()
	return c.proxies[name]
}

// closeProxy 关闭本会话内的指定代理，成功返回 true（管理面板操作用）
func (c *ClientSession) closeProxy(name string) bool {
	c.proxiesMu.Lock()
	p, ok := c.proxies[name]
	if ok {
		delete(c.proxies, name)
	}
	c.proxiesMu.Unlock()
	if !ok {
		return false
	}
	p.Stop()
	c.server.UnregisterProxy(p.proxyType, p.remotePort)
	return true
}

// getPublicAddr 获取公网地址（供 SDP 重写使用，优先返回解析后的 IP）
func (c *ClientSession) getPublicAddr() string {
	if c.server.publicIP != "" {
		return c.server.publicIP
	}
	if c.server.cfg.PublicAddr != "" {
		return c.server.cfg.PublicAddr
	}
	return c.server.cfg.BindAddr
}

// getOrCreateRTPRelays 为 SIP 消息中的 SDP 媒体条目分配 RTP relay。
// 若该 Call-ID 已有 relay 则复用，否则新建。
// owner 为触发本次分配（即 SDP 所属）的代理，中继的媒体流量计入该代理的统计。
// 返回 map[mediaIdx]publicPort 供 SDP 改写使用。
func (c *ClientSession) getOrCreateRTPRelays(callID string, entries []sip.MediaEntry, owner *ProxyInfo) map[int]int {
	if callID == "" || len(entries) == 0 {
		return nil
	}
	result := make(map[int]int)
	for idx, entry := range entries {
		key := fmt.Sprintf("%s#%d", callID, idx)
		c.rtpRelaysMu.Lock()
		relay, ok := c.rtpRelays[key]
		c.rtpRelaysMu.Unlock()
		if ok {
			result[idx] = relay.PublicPort
			continue
		}
		// 分配端口
		port := c.server.rtpPool.Alloc()
		if port == 0 {
			util.Logger.Warnw("rtp port pool exhausted", "callId", callID)
			continue
		}
		relay = &RTPRelay{
			ID:         key,
			CallID:     callID,
			MediaIdx:   idx,
			PublicPort: port,
			LocalIP:    entry.ConnAddr,
			LocalPort:  entry.Port,
			client:     c,
			closed:     make(chan struct{}),
			pool:       c.server.rtpPool,
		}
		if owner != nil {
			relay.stats = &owner.stats
		}
		if err := relay.Start(); err != nil {
			util.Logger.Errorw("rtp relay start", "relay", relay.ID, "err", err)
			c.server.rtpPool.Free(port)
			continue
		}
		c.rtpRelaysMu.Lock()
		c.rtpRelays[key] = relay
		c.rtpRelaysMu.Unlock()
		// 通知客户端建立中继
		req := protocol.NewRTPRelay{
			RelayID:    relay.ID,
			LocalIP:    entry.ConnAddr,
			LocalPort:  entry.Port,
			PublicPort: port,
		}
		if err := c.sendMsg(consts.TypeNewRTPRelay, req); err != nil {
			util.Logger.Errorw("send NewRTPRelay", "relay", relay.ID, "err", err)
		} else {
			util.Logger.Infow("rtp relay created", "relay", relay.ID, "callId", callID, "publicPort", port, "localAddr", fmt.Sprintf("%s:%d", entry.ConnAddr, entry.Port))
		}
		result[idx] = port
	}
	return result
}

// releaseRTPRelays 释放指定 Call-ID 的所有 RTP relay
func (c *ClientSession) releaseRTPRelays(callID string) {
	c.rtpRelaysMu.Lock()
	defer c.rtpRelaysMu.Unlock()
	for key, relay := range c.rtpRelays {
		if relay.CallID == callID {
			relay.Stop(true)
			delete(c.rtpRelays, key)
		}
	}
}
