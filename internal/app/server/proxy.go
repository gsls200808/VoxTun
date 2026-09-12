package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"voxTun/internal/app/common/consts"
	"voxTun/internal/app/common/protocol"
	"voxTun/internal/app/common/util"
	"voxTun/internal/app/protocol/sip"
)

// tlsHandshakeTimeout TLS 握手超时，避免半开连接长期占用
const tlsHandshakeTimeout = 10 * time.Second

// ProxyInfo 服务端代理信息
type ProxyInfo struct {
	name       string
	proxyType  string // tcp / udp (内部类型)
	origType   string // 原始类型 sip / iax
	localIP    string
	localPort  int
	remotePort int
	rewriteSDP bool
	client     *ClientSession
	startAt    time.Time
	// 运行期统计（转发路径上累加），供管理面板展示
	stats proxyStats

	// TCP 相关
	tcpListener net.Listener
	// sip-tls：TLS 配置。非空时监听器按连接首字节嗅探（TLS ClientHello / 明文）并分流
	tlsConfig *tls.Config
	// sipMode 为 true 时按 SIP 消息分帧桥接（含 SDP 改写 / RTP 中继），否则原样双向转发
	sipMode bool
	// 等待 work 连接的外部连接队列
	pendingConns   chan pendingConn
	pendingConnsMu sync.Mutex

	// UDP 相关
	udpConn *net.UDPConn
	// 外部对端地址 -> peer 信息
	udpPeers   map[string]*udpPeer
	udpPeersMu sync.RWMutex

	stopOnce sync.Once
	stopped  chan struct{}
}

// udpPeer UDP 外部对端信息
type udpPeer struct {
	addr *net.UDPAddr
}

// Start 启动代理监听
func (p *ProxyInfo) Start(srv *Server) error {
	p.stopped = make(chan struct{})
	p.startAt = time.Now()
	if p.proxyType == consts.ProxyTypeTCP {
		switch p.origType {
		case consts.ProxyTypeSIPTLS:
			if srv.tlsConfig == nil {
				return fmt.Errorf("sip-tls proxy %s requires tlsCertFile/tlsKeyFile in server config", p.name)
			}
			// sip-tls 监听器同时接受 TLS 与明文 SIP/TCP：按首字节嗅探分流，
			// 因此可与原 sip-tcp 合并到同一端口（如 5060）；两种连接都按 SIP 分帧处理
			p.tlsConfig = srv.tlsConfig
			p.sipMode = true
		case consts.ProxyTypeSIPTCP:
			// 明文 SIP over TCP：同样按 SIP 分帧，做 SDP 改写与 RTP 中继
			p.sipMode = true
		}
		return p.startTCPListener()
	}
	return p.startUDP()
}

// startTCPListener 启动 TCP 监听。
// p.tlsConfig 非空时按连接嗅探：TLS ClientHello 走 TLS 终止，其余按明文处理。
// 是否为 SIP 由 p.sipMode 决定：sipMode 下两种连接都按 SIP 消息分帧（含 SDP 改写 / RTP 中继），
// 否则一律原样双向转发。
func (p *ProxyInfo) startTCPListener() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.remotePort))
	if err != nil {
		return fmt.Errorf("listen tcp %d: %w", p.remotePort, err)
	}
	p.tcpListener = ln
	p.pendingConns = make(chan pendingConn, 16)
	go p.acceptTCP()
	go p.handlePendingConns()
	return nil
}

// pendingConn 已完成入站嗅探、等待 work 连接匹配的外部连接
type pendingConn struct {
	conn  net.Conn
	isTLS bool
}

// peekedConn 包装已完成首字节嗅探的连接：Read 先消费预读缓存，其余走底层连接
type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// sniffTLSConn 预读首字节判断该连接是否为 TLS 握手。
// TLS ClientHello 的记录类型固定为 0x16；明文 SIP 首字节必为方法名 ASCII（如 R/O/I）。
// 返回的连接保留预读数据，可继续正常读写；发生错误时返回 nil。
func sniffTLSConn(conn net.Conn) (net.Conn, bool) {
	br := bufio.NewReader(conn)
	b, err := br.Peek(1)
	if err != nil {
		_ = conn.Close()
		return nil, false
	}
	return &peekedConn{Conn: conn, r: br}, b[0] == 0x16
}

func (p *ProxyInfo) acceptTCP() {
	for {
		conn, err := p.tcpListener.Accept()
		if err != nil {
			select {
			case <-p.stopped:
				return
			default:
			}
			util.Logger.Errorw("tcp accept", "proxy", p.name, "err", err)
			return
		}
		if !p.client.server.ipFilter.AllowAddrLogged(conn.RemoteAddr(), "tcp proxy "+p.name) {
			_ = conn.Close()
			continue
		}
		// 嗅探 + 握手统一受超时保护，避免半开连接长期占用
		isTLS := false
		if p.tlsConfig != nil {
			_ = conn.SetReadDeadline(time.Now().Add(tlsHandshakeTimeout))
			nc, tlsDetected := sniffTLSConn(conn)
			if nc == nil {
				continue
			}
			conn = nc
			if tlsDetected {
				tc := tls.Server(conn, p.tlsConfig)
				if err := tc.Handshake(); err != nil {
					util.Logger.Warnw("tls handshake failed", "proxy", p.name, "remote", conn.RemoteAddr().String(), "err", err)
					_ = conn.Close()
					continue
				}
				conn = tc
				isTLS = true
			}
			_ = conn.SetReadDeadline(time.Time{})
		}
		select {
		case p.pendingConns <- pendingConn{conn: conn, isTLS: isTLS}:
		default:
			util.Logger.Warnw("pending conns full, closing", "proxy", p.name)
			_ = conn.Close()
		}
	}
}

func (p *ProxyInfo) handlePendingConns() {
	for {
		select {
		case <-p.stopped:
			return
		case pc := <-p.pendingConns:
			go p.handleTCPConn(pc.conn, pc.isTLS)
		}
	}
}

func (p *ProxyInfo) handleTCPConn(extConn net.Conn, isTLS bool) {
	p.stats.activeConns.Add(1)
	defer p.stats.activeConns.Add(-1)
	// 请求客户端新建 work 连接
	if err := p.client.RequestWorkConn(p.name); err != nil {
		util.Logger.Errorw("request work conn", "err", err)
		_ = extConn.Close()
		return
	}
	// 等待客户端连入的 work 连接（通过服务端 accept 新连接匹配）
	workConn := p.client.server.waitWorkConn(p.name)
	if workConn == nil {
		_ = extConn.Close()
		return
	}
	if p.sipMode {
		// SIP over TCP/TLS：按 SIP 消息分帧桥接，回程做 SDP 改写 / RTP 中继
		mode := "plain"
		if isTLS {
			mode = "tls"
		}
		util.Logger.Infow("sip proxy join", "proxy", p.name, "mode", mode, "remote", extConn.RemoteAddr().String())
		p.bridgeSIP(extConn, workConn)
	} else {
		util.Logger.Infow("tcp proxy join", "proxy", p.name, "remote", extConn.RemoteAddr().String())
		util.JoinCounted(extConn, workConn, p.stats.addIn, p.stats.addOut)
	}
	_ = extConn.Close()
	_ = workConn.Close()
}

// bridgeSIP 桥接「外部话机的 SIP 连接（TLS 或明文）」与「内网服务的 work 连接」。
// 两个方向均按 SIP over TCP 分帧；内网 -> 外部方向复用 SDP / 路由头重写与 RTP 中继。
func (p *ProxyInfo) bridgeSIP(extConn, workConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	// 外部话机 -> 内网服务：原样转发，仅检测 BYE 释放 RTP 中继
	go func() {
		defer wg.Done()
		p.pipeSIP(extConn, workConn, false, p.stats.addIn)
		if tc, ok := workConn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	// 内网服务 -> 外部话机：改写 SDP / 路由头并分配 RTP 中继
	go func() {
		defer wg.Done()
		p.pipeSIP(workConn, extConn, true, p.stats.addOut)
		if tc, ok := extConn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// pipeSIP 从 src 逐条读取 SIP 消息并写入 dst。
// fromInternal=true 表示「内网服务 -> 外部话机」方向，需要做 SDP / 路由头重写。
// count 用于累加该方向写出的字节数（流量统计）。
func (p *ProxyInfo) pipeSIP(src, dst net.Conn, fromInternal bool, count func(int)) {
	br := bufio.NewReader(src)
	for {
		msg, err := sip.ReadMessageFromStream(br)
		if err != nil {
			return
		}
		// 丢弃 CRLF keepalive 等空消息
		if len(bytes.TrimSpace(msg)) == 0 {
			continue
		}
		if fromInternal {
			msg = p.rewriteSIPForExternal(msg)
		} else {
			p.releaseRelayOnBye(msg)
		}
		if _, err := dst.Write(msg); err != nil {
			return
		}
		count(len(msg))
	}
}

// releaseRelayOnBye 检测到 BYE 请求时释放对应 Call-ID 的 RTP 中继
func (p *ProxyInfo) releaseRelayOnBye(data []byte) {
	if !p.rewriteSDP || !sip.IsSIP(data) {
		return
	}
	msg := sip.Parse(data)
	if msg == nil || !msg.IsRequest || msg.Method != "BYE" {
		return
	}
	if callID := msg.GetHeader("Call-ID"); callID != "" {
		p.client.releaseRTPRelays(callID)
	}
}

// rewriteSIPForExternal 对「内网服务 -> 外部对端」方向的 SIP 消息做 SDP / 路由头重写，
// 并按 SDP 媒体条目分配 RTP 中继。非 SIP 或未开启 rewriteSDP 时原样返回。
func (p *ProxyInfo) rewriteSIPForExternal(data []byte) []byte {
	if !p.rewriteSDP || !sip.IsSIP(data) {
		return data
	}
	msg := sip.Parse(data)
	if msg == nil {
		return data
	}
	p.releaseRelayOnBye(data)
	publicAddr := p.client.getPublicAddr()
	entries := msg.ExtractMediaEntries()
	if len(entries) > 0 {
		callID := msg.GetHeader("Call-ID")
		relayPorts := p.client.getOrCreateRTPRelays(callID, entries, p)
		if len(relayPorts) > 0 {
			msg.RewriteSDPWithRelays(publicAddr, relayPorts)
		} else {
			// 无 relay 也至少改 c=/o= 地址（保持原行为）
			msg.RewriteSDP(publicAddr, 0)
		}
	} else {
		msg.RewriteSDP(publicAddr, 0)
	}
	// 改写 Contact / Record-Route 里的内网地址，保证外部对端 ACK/BYE 能路由回来
	msg.RewriteRoutingHeaders(publicAddr)
	return msg.Bytes()
}

func (p *ProxyInfo) startUDP() error {
	addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: p.remotePort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %d: %w", p.remotePort, err)
	}
	p.udpConn = conn
	go p.readUDP()
	return nil
}

func (p *ProxyInfo) readUDP() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := p.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.stopped:
				return
			default:
			}
			util.Logger.Errorw("udp read", "proxy", p.name, "err", err)
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		if !p.client.server.ipFilter.AllowAddrLogged(raddr, fmt.Sprintf("udp proxy %s:%d", p.name, p.remotePort)) {
			continue
		}
		p.handleUDPPacket(data, raddr)
	}
}

func (p *ProxyInfo) handleUDPPacket(data []byte, raddr *net.UDPAddr) {
	// 记录外部对端
	key := raddr.String()
	p.udpPeersMu.Lock()
	if _, ok := p.udpPeers[key]; !ok {
		p.udpPeers[key] = &udpPeer{addr: raddr}
	}
	p.udpPeersMu.Unlock()
	p.stats.addIn(len(data))

	// BYE 检测：任一方向的 BYE 都释放该 Call-ID 的 RTP relay
	if p.rewriteSDP && p.origType == consts.ProxyTypeSIP && sip.IsSIP(data) {
		if msg := sip.Parse(data); msg != nil {
			if msg.IsRequest && msg.Method == "BYE" {
				callID := msg.GetHeader("Call-ID")
				if callID != "" {
					p.client.releaseRTPRelays(callID)
				}
			}
		}
	}

	// SIP SDP 重写（外部 -> 内部方向一般不需要重写 SDP，但记录会话）
	// 这里直接转发给客户端
	pkt := protocol.UDPPacket{
		ProxyName:  p.name,
		RemoteAddr: key,
		Data:       data,
	}
	if err := p.client.sendMsg(consts.TypeUDPPacket, pkt); err != nil {
		util.Logger.Errorw("send udp packet to client", "err", err)
	}
}

// SendUDPPacketToPeer 服务端收到客户端回传的 UDP 包，转发给外部对端
func (p *ProxyInfo) SendUDPPacketToPeer(remoteAddr string, data []byte) {
	p.udpPeersMu.RLock()
	peer, ok := p.udpPeers[remoteAddr]
	p.udpPeersMu.RUnlock()
	if !ok {
		util.Logger.Warnw("unknown udp peer", "addr", remoteAddr)
		return
	}
	// SIP：改写 SDP / 路由头并分配 RTP 中继（仅 sip 类型的 rewriteSDP 开启时）
	if p.origType == consts.ProxyTypeSIP {
		data = p.rewriteSIPForExternal(data)
	}
	_, err := p.udpConn.WriteToUDP(data, peer.addr)
	if err != nil {
		util.Logger.Errorw("udp write to peer", "err", err)
		return
	}
	p.stats.addOut(len(data))
}

// connCount 当前连接数：TCP 代理为活动外部连接数，UDP 代理为已见到的外部对端数
func (p *ProxyInfo) connCount() int64 {
	if p.proxyType == consts.ProxyTypeTCP {
		return p.stats.activeConns.Load()
	}
	p.udpPeersMu.RLock()
	n := int64(len(p.udpPeers))
	p.udpPeersMu.RUnlock()
	return n
}

// Stop 停止代理
func (p *ProxyInfo) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopped)
		if p.tcpListener != nil {
			_ = p.tcpListener.Close()
		}
		if p.udpConn != nil {
			_ = p.udpConn.Close()
		}
	})
}
