package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"voxTun/internal/app/common/config"
	"voxTun/internal/app/common/ipfilter"
	"voxTun/internal/app/common/util"
)

// Server VoxTun 服务端
type Server struct {
	cfg        *config.ServerConfig
	configPath string // 配置文件路径，面板修改黑白名单后回写
	listener   net.Listener
	clients    map[string]*ClientSession // key: 客户端唯一标识（这里用远程地址）
	clientsMu  sync.RWMutex
	// remotePort -> *ProxyInfo，用于公网监听查找
	proxies   map[string]*ProxyInfo
	proxiesMu sync.RWMutex
	workMgr   *workConnManager
	rtpPool   *rtpPortPool
	publicIP  string // publicAddr 解析后的公网 IP（用于 SDP 重写）
	ipFilter  *ipfilter.Filter
	ipMu      sync.Mutex  // 串行化面板对黑白名单的修改
	tlsConfig *tls.Config // sip-tls 代理使用的 TLS 配置（证书未配置时为 nil）
	startAt   time.Time
	web       *webServer // 管理面板（未配置 webServer.port 时为 nil）
}

// NewServer 创建服务端，configPath 为配置文件路径（面板回写黑白名单用）
func NewServer(cfg *config.ServerConfig, configPath string) (*Server, error) {
	ipFilter, err := ipfilter.New(cfg.IPFilter)
	if err != nil {
		return nil, fmt.Errorf("init ip filter: %w", err)
	}
	s := &Server{
		cfg:        cfg,
		configPath: configPath,
		clients:    make(map[string]*ClientSession),
		proxies:    make(map[string]*ProxyInfo),
		workMgr:    newWorkConnManager(),
		rtpPool:    newRTPPortPool(cfg),
		publicIP:   resolvePublicIP(cfg.PublicAddr),
		ipFilter:   ipFilter,
		startAt:    time.Now(),
	}
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, fmt.Errorf("tlsCertFile and tlsKeyFile must be set together")
		}
		reloader, err := newCertReloader(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		s.tlsConfig = &tls.Config{
			GetCertificate: reloader.getCertificate,
			MinVersion:     tls.VersionTLS12,
		}
		util.Logger.Infow("tls config loaded", "cert", cfg.TLSCertFile)
	}
	if ipFilter.Enabled() {
		util.Logger.Infow("ip filter enabled", "allow", len(cfg.IPFilter.AllowList), "deny", len(cfg.IPFilter.DenyList))
	}
	return s, nil
}

// resolvePublicIP 将 publicAddr 解析为 IP 字面量（SDP 的 c= 字段要求 IP，不能是域名）
func resolvePublicIP(addr string) string {
	if addr == "" {
		return ""
	}
	if net.ParseIP(addr) != nil {
		return addr
	}
	if addrs, err := net.LookupHost(addr); err == nil {
		for _, a := range addrs {
			if net.ParseIP(a) != nil {
				return a
			}
		}
	}
	util.Logger.Warnw("failed to resolve publicAddr to IP, SDP will contain hostname", "publicAddr", addr)
	return addr
}

// Run 启动服务端
func (s *Server) Run() error {
	// 管理面板启动失败不影响隧道功能，只记录错误
	if err := s.startWebServer(); err != nil {
		util.Logger.Errorw("start dashboard failed", "err", err)
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.BindAddr, s.cfg.BindPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.listener = ln
	util.Logger.Infow("voxsrv listening", "addr", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			util.Logger.Errorw("accept error", "err", err)
			continue
		}
		go s.handleIncomingConn(conn)
	}
}

// handleClient 已废弃，统一由 handleIncomingConn 处理
func (s *Server) handleClient(conn net.Conn) {
	s.handleIncomingConn(conn)
}

func (s *Server) addClient(c *ClientSession) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	s.clients[c.conn.RemoteAddr().String()] = c
}

func (s *Server) removeClient(c *ClientSession) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	delete(s.clients, c.conn.RemoteAddr().String())
}

// proxyKey 生成代理的唯一键：协议:端口
func proxyKey(proxyType string, port int) string {
	return fmt.Sprintf("%s:%d", proxyType, port)
}

// RegisterProxy 注册一个代理
func (s *Server) RegisterProxy(p *ProxyInfo) error {
	s.proxiesMu.Lock()
	defer s.proxiesMu.Unlock()
	key := proxyKey(p.proxyType, p.remotePort)
	if _, ok := s.proxies[key]; ok {
		return fmt.Errorf("remote %s port %d already in use", p.proxyType, p.remotePort)
	}
	if !s.cfg.IsPortAllowed(p.remotePort) {
		return fmt.Errorf("remote port %d not allowed", p.remotePort)
	}
	s.proxies[key] = p
	return nil
}

// UnregisterProxy 注销代理
func (s *Server) UnregisterProxy(proxyType string, remotePort int) {
	s.proxiesMu.Lock()
	defer s.proxiesMu.Unlock()
	delete(s.proxies, proxyKey(proxyType, remotePort))
}

// Shutdown 关闭服务端
func (s *Server) Shutdown() {
	if s.web != nil {
		_ = s.web.httpSrv.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.clientsMu.Lock()
	for _, c := range s.clients {
		c.Close()
	}
	s.clientsMu.Unlock()
	time.Sleep(100 * time.Millisecond)
}
