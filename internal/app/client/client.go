package client

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"voxTun/internal/app/common/config"
	"voxTun/internal/app/common/consts"
	"voxTun/internal/app/common/protocol"
	"voxTun/internal/app/common/util"
)

// Client VoxTun 客户端
type Client struct {
	cfg        *config.ClientConfig
	conn       net.Conn
	proxies    map[string]*ProxyRunner
	proxiesMu  sync.RWMutex
	sendMu     sync.Mutex
	closeOnce  sync.Once
	closed     chan struct{}
}

// NewClient 创建客户端
func NewClient(cfg *config.ClientConfig) *Client {
	return &Client{
		cfg:     cfg,
		proxies: make(map[string]*ProxyRunner),
		closed:  make(chan struct{}),
	}
}

// Run 启动客户端
func (c *Client) Run() error {
	if err := c.connectControl(); err != nil {
		return err
	}
	if err := c.auth(); err != nil {
		return err
	}
	// 注册所有代理
	if err := c.registerProxies(); err != nil {
		return err
	}
	// 启动心跳
	go c.heartbeat()
	// 处理消息
	return c.runLoop()
}

func (c *Client) connectControl() error {
	addr := fmt.Sprintf("%s:%d", c.cfg.ServerAddr, c.cfg.ServerPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial server %s: %w", addr, err)
	}
	util.SetKeepAlive(conn)
	c.conn = conn
	util.Logger.Infow("connected to server", "addr", addr)
	return nil
}

func (c *Client) auth() error {
	hostname, _ := os.Hostname()
	auth := protocol.Auth{
		Token:    c.cfg.Token,
		Version:  "1.0.0",
		Hostname: hostname,
	}
	if err := c.sendMsg(consts.TypeAuth, auth); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}
	msgType, payload, err := protocol.ReadMsg(c.conn)
	if err != nil {
		return fmt.Errorf("read auth resp: %w", err)
	}
	if msgType != consts.TypeAuthResp {
		return fmt.Errorf("expected auth resp, got %d", msgType)
	}
	var resp protocol.AuthResp
	if err := protocol.Decode(payload, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("auth failed: %s", resp.Error)
	}
	util.Logger.Infow("authenticated with server")
	return nil
}

func (c *Client) registerProxies() error {
	for _, pc := range c.cfg.Proxies {
		req := protocol.NewProxy{
			ProxyName:  pc.Name,
			ProxyType:  pc.Type,
			LocalIP:    pc.LocalIP,
			LocalPort:  pc.LocalPort,
			RemotePort: pc.RemotePort,
			RewriteSDP: pc.RewriteSDP,
		}
		if err := c.sendMsg(consts.TypeNewProxy, req); err != nil {
			return fmt.Errorf("send NewProxy %s: %w", pc.Name, err)
		}
		msgType, payload, err := protocol.ReadMsg(c.conn)
		if err != nil {
			return fmt.Errorf("read NewProxyResp %s: %w", pc.Name, err)
		}
		if msgType != consts.TypeNewProxyResp {
			return fmt.Errorf("expected NewProxyResp, got %d", msgType)
		}
		var resp protocol.NewProxyResp
		if err := protocol.Decode(payload, &resp); err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("proxy %s failed: %s", pc.Name, resp.Error)
		}
		runner := &ProxyRunner{
			client:      c,
			cfg:         pc,
			udpSessions: make(map[string]*udpSession),
		}
		c.proxiesMu.Lock()
		c.proxies[pc.Name] = runner
		c.proxiesMu.Unlock()
		util.Logger.Infow("proxy registered", "name", pc.Name, "type", pc.Type, "remotePort", resp.RemotePort)
	}
	return nil
}

func (c *Client) runLoop() error {
	for {
		msgType, payload, err := protocol.ReadMsg(c.conn)
		if err != nil {
			select {
			case <-c.closed:
				return nil
			default:
			}
			return fmt.Errorf("read control msg: %w", err)
		}
		switch msgType {
		case consts.TypePong:
			// 心跳响应，忽略
		case consts.TypeNewWorkConn:
			c.handleNewWorkConn(payload)
		case consts.TypeUDPPacket:
			c.handleUDPPacket(payload)
		case consts.TypeNewRTPRelay:
			c.handleNewRTPRelay(payload)
		case consts.TypeCloseRTPRelay:
			c.handleCloseRTPRelay(payload)
		default:
			util.Logger.Warnw("unknown msg type", "type", msgType)
		}
	}
}

func (c *Client) heartbeat() {
	ticker := time.NewTicker(consts.HeartbeatInterval * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			if err := c.sendMsg(consts.TypePing, protocol.Ping{Timestamp: time.Now().Unix()}); err != nil {
				util.Logger.Errorw("send ping", "err", err)
				c.Close()
				return
			}
		}
	}
}

func (c *Client) sendMsg(msgType byte, payload interface{}) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return protocol.WriteMsg(c.conn, msgType, payload)
}

// Close 关闭客户端
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

// GetProxy 获取代理运行器
func (c *Client) GetProxy(name string) *ProxyRunner {
	c.proxiesMu.RLock()
	defer c.proxiesMu.RUnlock()
	return c.proxies[name]
}
