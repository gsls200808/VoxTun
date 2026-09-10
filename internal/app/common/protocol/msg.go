package protocol

// Auth 客户端认证请求
type Auth struct {
	Token    string `json:"token"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
}

// AuthResp 认证响应
type AuthResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// NewProxy 客户端请求新建代理
type NewProxy struct {
	ProxyName  string `json:"proxyName"`
	ProxyType  string `json:"proxyType"` // tcp / udp / sip / iax
	LocalIP    string `json:"localIP"`
	LocalPort  int    `json:"localPort"`
	RemotePort int    `json:"remotePort"`
	RewriteSDP bool   `json:"rewriteSDP"`
}

// NewProxyResp 新建代理响应
type NewProxyResp struct {
	ProxyName string `json:"proxyName"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	RemotePort int   `json:"remotePort,omitempty"`
}

// NewWorkConn 服务端请求客户端新建工作连接
type NewWorkConn struct {
	ProxyName string `json:"proxyName"`
}

// StartWorkConn 客户端启动工作连接
type StartWorkConn struct {
	ProxyName string `json:"proxyName"`
}

// ProxyClosed 代理关闭通知
type ProxyClosed struct {
	ProxyName string `json:"proxyName"`
	Reason    string `json:"reason,omitempty"`
}

// UDPPacket UDP 数据包（用于 SIP/IAX 等 UDP 信令中继）
type UDPPacket struct {
	ProxyName string `json:"proxyName"`
	// 远端地址（公网对端），格式 host:port
	RemoteAddr string `json:"remoteAddr"`
	// 数据包内容
	Data []byte `json:"data"`
}

// Ping 心跳
type Ping struct {
	Timestamp int64 `json:"timestamp"`
}

// Pong 心跳响应
type Pong struct {
	Timestamp int64 `json:"timestamp"`
}

// NewRTPRelay 服务端请求客户端为指定内网 RTP 端口建立中继
type NewRTPRelay struct {
	RelayID    string `json:"relayId"`    // 服务端分配的唯一 ID
	LocalIP    string `json:"localIP"`    // 内网 RTP 服务地址（来自 SDP c=）
	LocalPort  int    `json:"localPort"`  // 内网 RTP 端口（来自 SDP m=）
	PublicPort int    `json:"publicPort"` // 服务端分配的公网 RTP 端口
}

// NewRTPRelayResp 客户端中继建立响应
type NewRTPRelayResp struct {
	RelayID string `json:"relayId"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// CloseRTPRelay 服务端通知客户端关闭 RTP 中继
type CloseRTPRelay struct {
	RelayID string `json:"relayId"`
}
