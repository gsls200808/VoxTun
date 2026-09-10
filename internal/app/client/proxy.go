package client

import (
	"fmt"
	"net"
	"sync"
	"time"

	"voxTun/internal/app/common/config"
	"voxTun/internal/app/common/consts"
	"voxTun/internal/app/common/protocol"
	"voxTun/internal/app/common/util"
)

// ProxyRunner 客户端代理运行器
type ProxyRunner struct {
	client *Client
	cfg    config.ProxyConfig

	// UDP: 远端对端地址 -> 已连接到本地服务的 UDP socket
	udpSessions   map[string]*udpSession
	udpSessionsMu sync.Mutex
}

// udpSession 一个 UDP 会话：对应一个外部对端，通过已连接的 UDP socket 与本地服务通信
type udpSession struct {
	conn      *net.UDPConn
	peerAddr  string
	closeOnce sync.Once
}

// handleNewWorkConn 处理服务端请求新建 work 连接（TCP 代理）
func (c *Client) handleNewWorkConn(payload []byte) {
	var req protocol.NewWorkConn
	if err := protocol.Decode(payload, &req); err != nil {
		util.Logger.Errorw("decode NewWorkConn", "err", err)
		return
	}
	runner := c.GetProxy(req.ProxyName)
	if runner == nil {
		util.Logger.Warnw("NewWorkConn for unknown proxy", "name", req.ProxyName)
		return
	}
	go runner.startWorkConn()
}

// handleNewRTPRelay 处理服务端 RTP 中继建立请求
// 复用 ProxyRunner（type=udp）机制：创建一个虚拟 runner，proxyName=relayID，
// localIP/Port=SDP 里的媒体地址。后续 RTP 包的转发逻辑完全复用 handleUDPPacket。
func (c *Client) handleNewRTPRelay(payload []byte) {
	var req protocol.NewRTPRelay
	if err := protocol.Decode(payload, &req); err != nil {
		util.Logger.Errorw("decode NewRTPRelay", "err", err)
		return
	}
	// 创建虚拟 runner
	runner := &ProxyRunner{
		client: c,
		cfg: config.ProxyConfig{
			Name:      req.RelayID,
			Type:      consts.ProxyTypeUDP,
			LocalIP:   req.LocalIP,
			LocalPort: req.LocalPort,
		},
		udpSessions: make(map[string]*udpSession),
	}
	c.proxiesMu.Lock()
	c.proxies[req.RelayID] = runner
	c.proxiesMu.Unlock()
	util.Logger.Infow("rtp relay runner created", "relayId", req.RelayID, "local", fmt.Sprintf("%s:%d", req.LocalIP, req.LocalPort))
	// 回响应
	if err := c.sendMsg(consts.TypeNewRTPRelayResp, protocol.NewRTPRelayResp{
		RelayID: req.RelayID,
		OK:      true,
	}); err != nil {
		util.Logger.Errorw("send NewRTPRelayResp", "err", err)
	}
}

// handleCloseRTPRelay 处理服务端 RTP 中继关闭通知
func (c *Client) handleCloseRTPRelay(payload []byte) {
	var req protocol.CloseRTPRelay
	if err := protocol.Decode(payload, &req); err != nil {
		util.Logger.Errorw("decode CloseRTPRelay", "err", err)
		return
	}
	c.proxiesMu.Lock()
	if runner, ok := c.proxies[req.RelayID]; ok {
		// 关闭所有 UDP sessions
		runner.udpSessionsMu.Lock()
		for _, sess := range runner.udpSessions {
			sess.closeOnce.Do(func() {
				_ = sess.conn.Close()
			})
		}
		runner.udpSessions = make(map[string]*udpSession)
		runner.udpSessionsMu.Unlock()
		delete(c.proxies, req.RelayID)
	}
	c.proxiesMu.Unlock()
	util.Logger.Infow("rtp relay runner closed", "relayId", req.RelayID)
}

// startWorkConn 建立 work 连接：连本地服务 + 连服务端，然后桥接
func (r *ProxyRunner) startWorkConn() {
	// 1. 连接本地服务
	localAddr := fmt.Sprintf("%s:%d", r.cfg.LocalIP, r.cfg.LocalPort)
	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		util.Logger.Errorw("dial local service", "proxy", r.cfg.Name, "addr", localAddr, "err", err)
		return
	}
	// 2. 连接服务端建立 work 连接
	serverAddr := fmt.Sprintf("%s:%d", r.client.cfg.ServerAddr, r.client.cfg.ServerPort)
	workConn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		util.Logger.Errorw("dial server for work conn", "err", err)
		_ = localConn.Close()
		return
	}
	util.SetKeepAlive(workConn)
	// 3. 发送 StartWorkConn
	if err := protocol.WriteMsg(workConn, consts.TypeStartWorkConn, protocol.StartWorkConn{ProxyName: r.cfg.Name}); err != nil {
		util.Logger.Errorw("send StartWorkConn", "err", err)
		_ = localConn.Close()
		_ = workConn.Close()
		return
	}
	util.Logger.Infow("work conn established", "proxy", r.cfg.Name)
	// 4. 桥接
	util.Join(localConn, workConn)
	_ = localConn.Close()
	_ = workConn.Close()
}

// handleUDPPacket 处理服务端转发的 UDP 包（UDP / SIP / IAX）
func (c *Client) handleUDPPacket(payload []byte) {
	var pkt protocol.UDPPacket
	if err := protocol.Decode(payload, &pkt); err != nil {
		util.Logger.Errorw("decode UDPPacket", "err", err)
		return
	}
	runner := c.GetProxy(pkt.ProxyName)
	if runner == nil {
		util.Logger.Warnw("UDPPacket for unknown proxy", "name", pkt.ProxyName)
		return
	}
	runner.forwardUDPToLocal(&pkt)
}

// forwardUDPToLocal 将来自外部对端的 UDP 包转发给本地服务，并启动读取响应
func (r *ProxyRunner) forwardUDPToLocal(pkt *protocol.UDPPacket) {
	r.udpSessionsMu.Lock()
	sess, ok := r.udpSessions[pkt.RemoteAddr]
	if !ok {
		// 为该外部对端创建一个已连接到本地服务的 UDP socket
		localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", r.cfg.LocalIP, r.cfg.LocalPort))
		if err != nil {
			util.Logger.Errorw("resolve local udp addr", "err", err)
			r.udpSessionsMu.Unlock()
			return
		}
		conn, err := net.DialUDP("udp", nil, localAddr)
		if err != nil {
			util.Logger.Errorw("dial local udp", "err", err)
			r.udpSessionsMu.Unlock()
			return
		}
		sess = &udpSession{
			conn:     conn,
			peerAddr: pkt.RemoteAddr,
		}
		r.udpSessions[pkt.RemoteAddr] = sess
		r.udpSessionsMu.Unlock()
		// 启动读取本地服务响应的 goroutine
		go r.readLocalUDP(sess)
	} else {
		r.udpSessionsMu.Unlock()
	}

	// 发送数据到本地服务
	if _, err := sess.conn.Write(pkt.Data); err != nil {
		util.Logger.Errorw("write to local udp", "err", err)
	}
}

// readLocalUDP 持续读取本地服务的响应，转发回服务端
func (r *ProxyRunner) readLocalUDP(sess *udpSession) {
	buf := make([]byte, 65535)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, err := sess.conn.Read(buf)
		if err != nil {
			break
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		// 回传给服务端
		resp := protocol.UDPPacket{
			ProxyName:  r.cfg.Name,
			RemoteAddr: sess.peerAddr,
			Data:       data,
		}
		if err := r.client.sendMsg(consts.TypeUDPPacket, resp); err != nil {
			util.Logger.Errorw("send udp resp to server", "err", err)
			break
		}
	}
	sess.closeOnce.Do(func() {
		_ = sess.conn.Close()
	})
	r.udpSessionsMu.Lock()
	delete(r.udpSessions, sess.peerAddr)
	r.udpSessionsMu.Unlock()
}
