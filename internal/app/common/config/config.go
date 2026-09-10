package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	BindPort      int    `yaml:"bindPort"`      // 控制连接监听端口
	BindAddr      string `yaml:"bindAddr"`      // 控制连接监听地址
	PublicAddr    string `yaml:"publicAddr"`    // 公网地址（用于 SDP 重写）
	Token         string `yaml:"token"`         // 客户端认证 token
	LogLevel      string `yaml:"logLevel"`      // 日志级别
	MaxPoolCount  int    `yaml:"maxPoolCount"`  // 最大连接池数量
	UDPPacketSize int    `yaml:"udpPacketSize"` // UDP 包缓冲大小
	AllowPorts    []PortRange `yaml:"allowPorts"` // 允许客户端代理的端口范围
	IPFilter      IPFilterConfig `yaml:"ipFilter"` // IP 黑白名单过滤
}

// PortRange 端口范围
type PortRange struct {
	Start int `yaml:"start"`
	End   int `yaml:"end"`
}

// IPFilterConfig IP 黑白名单配置
// 黑名单优先级高于白名单；白名单非空时，仅放行白名单内的地址。
// 过滤对控制连接、TCP/UDP 代理以及 RTP 中继的所有外部对端生效，
// 因此白名单中需要同时包含客户端（voxcli）与外部话机的 IP。
type IPFilterConfig struct {
	Enable    bool     `yaml:"enable"`    // 是否启用，默认 false
	AllowList []string `yaml:"allowList"` // 白名单，支持 IP 或 CIDR
	DenyList  []string `yaml:"denyList"`  // 黑名单，支持 IP 或 CIDR
}

// ClientConfig 客户端配置
type ClientConfig struct {
	ServerAddr string `yaml:"serverAddr"` // 服务端地址
	ServerPort int    `yaml:"serverPort"` // 服务端控制端口
	Token      string `yaml:"token"`      // 认证 token
	LogLevel   string `yaml:"logLevel"`   // 日志级别
	Proxies    []ProxyConfig `yaml:"proxies"`
}

// ProxyConfig 单个代理配置
type ProxyConfig struct {
	Name       string `yaml:"name"`       // 代理名称
	Type       string `yaml:"type"`       // tcp / udp / sip / iax
	LocalIP    string `yaml:"localIP"`    // 内网服务地址
	LocalPort  int    `yaml:"localPort"`  // 内网服务端口
	RemotePort int    `yaml:"remotePort"` // 公网暴露端口
	RewriteSDP bool   `yaml:"rewriteSDP"` // 是否重写 SDP（仅 sip 生效）
}

// DefaultServerConfig 默认服务端配置
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		BindPort:      7000,
		BindAddr:      "0.0.0.0",
		PublicAddr:    "",
		Token:         "",
		LogLevel:      "info",
		MaxPoolCount:  5,
		UDPPacketSize: 1500,
	}
}

// DefaultClientConfig 默认客户端配置
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerPort: 7000,
		LogLevel:   "info",
	}
}

// LoadServerConfig 加载服务端配置
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultServerConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadClientConfig 加载客户端配置
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultClientConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// IsPortAllowed 检查端口是否在允许范围内
func (s *ServerConfig) IsPortAllowed(port int) bool {
	if len(s.AllowPorts) == 0 {
		return true
	}
	for _, r := range s.AllowPorts {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}
