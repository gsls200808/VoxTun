package consts

// Version 版本号，用于客户端握手与管理面板展示
const Version = "1.0.0"

// 服务类型
const (
	ProxyTypeTCP    = "tcp"
	ProxyTypeUDP    = "udp"
	ProxyTypeSIP    = "sip"     // SIP 信令 (默认 UDP 5060)
	ProxyTypeIAX    = "iax"     // IAX 信令 (UDP 4569)
	ProxyTypeSIPTCP = "sip-tcp" // SIP over TCP（明文，服务端做 SDP 改写与 RTP 中继）
	ProxyTypeSIPTLS = "sip-tls" // SIP over TLS（服务端原生终止 TLS，内部走 TCP 中继）
)

// 消息类型
const (
	TypeAuth          byte = 0x09
	TypeAuthResp      byte = 0x0A
	TypeNewProxy      byte = 0x01
	TypeNewProxyResp  byte = 0x02
	TypeNewWorkConn   byte = 0x03
	TypeStartWorkConn byte = 0x04
	TypeProxyClosed   byte = 0x05
	TypePing          byte = 0x06
	TypePong          byte = 0x07
	TypeUDPPacket     byte = 0x08
	TypeNewRTPRelay     byte = 0x0B // S→C: 请求客户端为 RTP 端口建立中继
	TypeNewRTPRelayResp byte = 0x0C // C→S: 中继建立结果
	TypeCloseRTPRelay   byte = 0x0D // S→C: 释放 RTP 中继
)

// 默认端口
const (
	DefaultServerBindPort = 7000 // 服务端控制连接监听端口
	DefaultSIPPort        = 5060
	DefaultSIPTLSPort     = 5061
	DefaultIAXPort        = 4569
)

// 最大包长
const (
	MaxPacketSize = 1024 * 1024 // 1MB
)

// 心跳间隔
const (
	HeartbeatInterval = 30 // 秒
	HeartbeatTimeout  = 90 // 秒
)
