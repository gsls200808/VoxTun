package server

import (
	"fmt"
	"net"
	"sync"

	"voxTun/internal/app/common/consts"
	"voxTun/internal/app/common/protocol"
	"voxTun/internal/app/common/util"
	"voxTun/internal/app/protocol/sip"
)

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

	// TCP 相关
	tcpListener net.Listener
	// 等待 work 连接的外部连接队列
	pendingConns   chan net.Conn
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
	if p.proxyType == consts.ProxyTypeTCP {
		return p.startTCP()
	}
	return p.startUDP()
}

func (p *ProxyInfo) startTCP() error {
	addr := fmt.Sprintf(":%d", p.remotePort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %d: %w", p.remotePort, err)
	}
	p.tcpListener = ln
	p.pendingConns = make(chan net.Conn, 16)
	go p.acceptTCP()
	go p.handlePendingConns()
	return nil
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
		select {
		case p.pendingConns <- conn:
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
		case conn := <-p.pendingConns:
			go p.handleTCPConn(conn)
		}
	}
}

func (p *ProxyInfo) handleTCPConn(extConn net.Conn) {
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
	util.Logger.Infow("tcp proxy join", "proxy", p.name, "remote", extConn.RemoteAddr().String())
	util.Join(extConn, workConn)
	_ = extConn.Close()
	_ = workConn.Close()
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
	// 若是 SIP 响应/请求且需要重写 SDP
	if p.rewriteSDP && p.origType == consts.ProxyTypeSIP && sip.IsSIP(data) {
		if msg := sip.Parse(data); msg != nil {
			// BYE 检测
			if msg.IsRequest && msg.Method == "BYE" {
				callID := msg.GetHeader("Call-ID")
				if callID != "" {
					p.client.releaseRTPRelays(callID)
				}
			}
			// 为 SDP 中的媒体条目分配 RTP relay
			publicAddr := p.client.getPublicAddr()
			entries := msg.ExtractMediaEntries()
			if len(entries) > 0 {
				callID := msg.GetHeader("Call-ID")
				relayPorts := p.client.getOrCreateRTPRelays(callID, entries)
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
			data = msg.Bytes()
		}
	}
	_, err := p.udpConn.WriteToUDP(data, peer.addr)
	if err != nil {
		util.Logger.Errorw("udp write to peer", "err", err)
	}
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
