package server

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

// rtpPortPool RTP 端口分配器（从 AllowPorts 中 >=10000 的段分配）
type rtpPortPool struct {
	mu     sync.Mutex
	used   map[int]bool
	ranges []config.PortRange
}

func newRTPPortPool(cfg *config.ServerConfig) *rtpPortPool {
	var ranges []config.PortRange
	for _, r := range cfg.AllowPorts {
		if r.End >= 10000 {
			// 只取 >=10000 的段，避免占用信令端口
			start := r.Start
			if start < 10000 {
				start = 10000
			}
			ranges = append(ranges, config.PortRange{Start: start, End: r.End})
		}
	}
	if len(ranges) == 0 {
		// 默认 10000-20000
		ranges = []config.PortRange{{Start: 10000, End: 20000}}
	}
	return &rtpPortPool{
		used:   make(map[int]bool),
		ranges: ranges,
	}
}

// Alloc 分配一个未用端口
func (p *rtpPortPool) Alloc() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.ranges {
		for port := r.Start; port <= r.End; port++ {
			if !p.used[port] {
				p.used[port] = true
				return port
			}
		}
	}
	return 0
}

// Free 释放端口
func (p *rtpPortPool) Free(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, port)
}

// RTPRelay 一条 RTP 中继
type RTPRelay struct {
	ID         string
	CallID     string
	MediaIdx   int
	PublicPort int
	LocalIP    string
	LocalPort  int

	udpConn    *net.UDPConn
	client     *ClientSession
	peerAddr    *net.UDPAddr // 外部对端地址（首个 RTP 包学习）
	peerMu      sync.Mutex
	lastActive  time.Time
	closed      chan struct{}
	closeOnce   sync.Once
	pool        *rtpPortPool
}

// Start 在公网端口监听 UDP，启动 readLoop + idle 超时检查
func (r *RTPRelay) Start() error {
	addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: r.PublicPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %d: %w", r.PublicPort, err)
	}
	r.udpConn = conn
	r.lastActive = time.Now()
	go r.readLoop()
	go r.idleWatch()
	return nil
}

// readLoop 读取外部对端 RTP，封装为 UDPPacket 转发到客户端
func (r *RTPRelay) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
			}
			util.Logger.Errorw("rtp relay read", "relay", r.ID, "err", err)
			return
		}
		if !r.client.server.ipFilter.AllowAddrLogged(raddr, "rtp relay "+r.ID) {
			continue
		}
		r.lastActive = time.Now()
		// 学习对端地址
		r.peerMu.Lock()
		if r.peerAddr == nil {
			r.peerAddr = raddr
			util.Logger.Infow("rtp relay learned peer", "relay", r.ID, "peer", raddr.String())
		}
		r.peerMu.Unlock()

		data := make([]byte, n)
		copy(data, buf[:n])
		pkt := protocol.UDPPacket{
			ProxyName:  r.ID,
			RemoteAddr: raddr.String(),
			Data:       data,
		}
		if err := r.client.sendMsg(consts.TypeUDPPacket, pkt); err != nil {
			util.Logger.Errorw("rtp relay send to client", "relay", r.ID, "err", err)
		}
	}
}

// idleWatch 60 秒无包自动停止
func (r *RTPRelay) idleWatch() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.closed:
			return
		case <-ticker.C:
			if time.Since(r.lastActive) > 60*time.Second {
				util.Logger.Infow("rtp relay idle timeout", "relay", r.ID, "callId", r.CallID)
				r.Stop(true)
				return
			}
		}
	}
}

// SendToPeer 客户端回传的 RTP 包发给外部对端
func (r *RTPRelay) SendToPeer(data []byte) {
	r.peerMu.Lock()
	peer := r.peerAddr
	r.peerMu.Unlock()
	if peer == nil {
		// 还没学到对端，丢弃（外部话机应先发 RTP 才能学习地址）
		return
	}
	r.lastActive = time.Now()
	if _, err := r.udpConn.WriteToUDP(data, peer); err != nil {
		util.Logger.Errorw("rtp relay write to peer", "relay", r.ID, "err", err)
	}
}

// Stop 停止中继。notifyClient=true 时通知客户端关闭
func (r *RTPRelay) Stop(notifyClient bool) {
	r.closeOnce.Do(func() {
		close(r.closed)
		if r.udpConn != nil {
			_ = r.udpConn.Close()
		}
		if r.pool != nil {
			r.pool.Free(r.PublicPort)
		}
		if notifyClient && r.client != nil {
			_ = r.client.sendMsg(consts.TypeCloseRTPRelay, protocol.CloseRTPRelay{RelayID: r.ID})
		}
		util.Logger.Infow("rtp relay stopped", "relay", r.ID, "callId", r.CallID, "port", r.PublicPort)
	})
}
