package sip

import (
	"bytes"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Message 表示一条 SIP 消息
type Message struct {
	IsRequest bool
	// 请求行: Method Request-URI SIP-Version
	Method  string
	RequestURI string
	// 状态行: SIP-Version Status-Code Reason-Phrase
	StatusCode string
	ReasonPhrase string
	Version string
	Headers map[string]string
	HeaderOrder []string
	Body    []byte
}

// Parse 解析 SIP 消息
func Parse(data []byte) *Message {
	msg := &Message{
		Headers: make(map[string]string),
	}
	// 分离头部和 body
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	var headerPart, body []byte
	if idx >= 0 {
		headerPart = data[:idx]
		body = data[idx+4:]
	} else {
		headerPart = data
	}
	lines := strings.Split(string(headerPart), "\r\n")
	if len(lines) == 0 {
		return nil
	}
	firstLine := lines[0]
	if strings.HasPrefix(firstLine, "SIP/") {
		// 响应
		msg.IsRequest = false
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 1 {
			msg.Version = parts[0]
		}
		if len(parts) >= 2 {
			msg.StatusCode = parts[1]
		}
		if len(parts) >= 3 {
			msg.ReasonPhrase = parts[2]
		}
	} else {
		// 请求
		msg.IsRequest = true
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 1 {
			msg.Method = parts[0]
		}
		if len(parts) >= 2 {
			msg.RequestURI = parts[1]
		}
		if len(parts) >= 3 {
			msg.Version = parts[2]
		}
	}
	// 解析 headers
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		// 同名 header 合并（以逗号分隔）
		if existing, ok := msg.Headers[name]; ok {
			msg.Headers[name] = existing + ", " + value
		} else {
			msg.Headers[name] = value
			msg.HeaderOrder = append(msg.HeaderOrder, name)
		}
	}
	msg.Body = body
	return msg
}

// IsSIP 判断数据是否为 SIP 消息
func IsSIP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	s := string(data)
	// 请求: METHOD SP URI SP SIP/2.0
	if strings.HasPrefix(s, "INVITE ") || strings.HasPrefix(s, "ACK ") ||
		strings.HasPrefix(s, "BYE ") || strings.HasPrefix(s, "CANCEL ") ||
		strings.HasPrefix(s, "REGISTER ") || strings.HasPrefix(s, "OPTIONS ") ||
		strings.HasPrefix(s, "PRACK ") || strings.HasPrefix(s, "SUBSCRIBE ") ||
		strings.HasPrefix(s, "NOTIFY ") || strings.HasPrefix(s, "UPDATE ") ||
		strings.HasPrefix(s, "REFER ") || strings.HasPrefix(s, "MESSAGE ") ||
		strings.HasPrefix(s, "INFO ") || strings.HasPrefix(s, "PUBLISH ") {
		return true
	}
	// 响应: SIP/2.0 SP STATUS
	if strings.HasPrefix(s, "SIP/2.0 ") {
		return true
	}
	return false
}

// GetHeader 获取 header（大小写不敏感）
func (m *Message) GetHeader(name string) string {
	if v, ok := m.Headers[name]; ok {
		return v
	}
	// 大小写不敏感查找
	for k, v := range m.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// SetHeader 设置 header
func (m *Message) SetHeader(name, value string) {
	if _, ok := m.Headers[name]; !ok {
		m.HeaderOrder = append(m.HeaderOrder, name)
	}
	m.Headers[name] = value
}

// Bytes 序列化 SIP 消息
func (m *Message) Bytes() []byte {
	var buf bytes.Buffer
	if m.IsRequest {
		buf.WriteString(m.Method)
		buf.WriteString(" ")
		buf.WriteString(m.RequestURI)
		buf.WriteString(" ")
		buf.WriteString(m.Version)
	} else {
		buf.WriteString(m.Version)
		buf.WriteString(" ")
		buf.WriteString(m.StatusCode)
		buf.WriteString(" ")
		buf.WriteString(m.ReasonPhrase)
	}
	buf.WriteString("\r\n")
	for _, name := range m.HeaderOrder {
		buf.WriteString(name)
		buf.WriteString(": ")
		buf.WriteString(m.Headers[name])
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(m.Body)
	return buf.Bytes()
}

// RewriteSDP 重写 SDP 中的连接地址和媒体端口，使其指向公网中继地址
// publicAddr: 公网 IP/域名
// publicPort: 公网媒体端口（若为 0 则保留原端口）
// 返回是否修改过
func (m *Message) RewriteSDP(publicAddr string, publicPort int) bool {
	if len(m.Body) == 0 {
		return false
	}
	contentType := strings.ToLower(m.GetHeader("Content-Type"))
	if contentType != "" && !strings.Contains(contentType, "application/sdp") {
		return false
	}
	lines := strings.Split(string(m.Body), "\r\n")
	modified := false
	for i, line := range lines {
		// c=IN IP4 <addr>
		if strings.HasPrefix(line, "c=IN IP4 ") {
			lines[i] = "c=IN IP4 " + publicAddr
			modified = true
		}
		// o= 行: username id version network-type address-type address
		if strings.HasPrefix(line, "o=") {
			parts := strings.Split(line, " ")
			if len(parts) >= 6 {
				parts[5] = publicAddr
				lines[i] = strings.Join(parts, " ")
				modified = true
			}
		}
		// m= 行: media port ...
		if strings.HasPrefix(line, "m=") && publicPort > 0 {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				parts[1] = strconv.Itoa(publicPort)
				lines[i] = strings.Join(parts, " ")
				modified = true
			}
		}
	}
	if modified {
		m.Body = []byte(strings.Join(lines, "\r\n"))
		// 更新 Content-Length
		if cl := m.GetHeader("Content-Length"); cl != "" {
			m.SetHeader("Content-Length", strconv.Itoa(len(m.Body)))
		}
	}
	return modified
}

// ExtractMediaPort 从 SDP 中提取媒体端口，返回媒体类型和端口
func (m *Message) ExtractMediaPort() (mediaType string, port int, ok bool) {
	if len(m.Body) == 0 {
		return
	}
	lines := strings.Split(string(m.Body), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "m=") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				mediaType = strings.TrimPrefix(parts[0], "m=")
				if p, err := strconv.Atoi(parts[1]); err == nil {
					port = p
					ok = true
					return
				}
			}
		}
	}
	return
}

// ExtractMediaEntries 从 SDP 中提取所有媒体条目及关联的 c= 地址。
// 返回值按 m= 行出现顺序排列。每个条目包含媒体类型、端口、最近的 c= 地址（若无则用顶层 c=）
type MediaEntry struct {
	MediaType string
	Port      int
	ConnAddr  string // c=IN IP4 <addr> 中的 addr
}

// ExtractMediaEntries 提取 SDP 中所有媒体条目（含各自关联的 c= 地址）
func (m *Message) ExtractMediaEntries() []MediaEntry {
	if len(m.Body) == 0 {
		return nil
	}
	lines := strings.Split(string(m.Body), "\r\n")
	var entries []MediaEntry
	var topC, lastC string
	for _, line := range lines {
		if strings.HasPrefix(line, "c=IN IP4 ") {
			addr := strings.TrimPrefix(line, "c=IN IP4 ")
			if len(entries) == 0 {
				topC = addr
			}
			lastC = addr
		}
		if strings.HasPrefix(line, "m=") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				mt := strings.TrimPrefix(parts[0], "m=")
				if p, err := strconv.Atoi(parts[1]); err == nil {
					addr := lastC
					if addr == "" {
						addr = topC
					}
					entries = append(entries, MediaEntry{MediaType: mt, Port: p, ConnAddr: addr})
					// m= 行后的 c= 不再回填到顶层；清空 lastC 让后续 m= 必须自带或在 m 之后再有 c=
					lastC = ""
				}
			}
		}
	}
	return entries
}

// RewriteSDPWithRelays 按媒体索引改写 SDP。
// publicAddr: c= / o= 改成的公网地址
// relayPorts: map[媒体索引]公网端口（按 m= 行出现顺序从 0 开始）
// 返回是否修改过
func (m *Message) RewriteSDPWithRelays(publicAddr string, relayPorts map[int]int) bool {
	if len(m.Body) == 0 {
		return false
	}
	contentType := strings.ToLower(m.GetHeader("Content-Type"))
	if contentType != "" && !strings.Contains(contentType, "application/sdp") {
		return false
	}
	lines := strings.Split(string(m.Body), "\r\n")
	modified := false
	mediaIdx := -1
	for i, line := range lines {
		// c=IN IP4 <addr>
		if strings.HasPrefix(line, "c=IN IP4 ") {
			lines[i] = "c=IN IP4 " + publicAddr
			modified = true
		}
		// o= 行
		if strings.HasPrefix(line, "o=") {
			parts := strings.Split(line, " ")
			if len(parts) >= 6 {
				parts[5] = publicAddr
				lines[i] = strings.Join(parts, " ")
				modified = true
			}
		}
		// m= 行
		if strings.HasPrefix(line, "m=") {
			mediaIdx++
			if publicPort, ok := relayPorts[mediaIdx]; ok && publicPort > 0 {
				parts := strings.Split(line, " ")
				if len(parts) >= 2 {
					parts[1] = strconv.Itoa(publicPort)
					lines[i] = strings.Join(parts, " ")
					modified = true
				}
			}
		}
	}
	if modified {
		m.Body = []byte(strings.Join(lines, "\r\n"))
		if cl := m.GetHeader("Content-Length"); cl != "" {
			m.SetHeader("Content-Length", strconv.Itoa(len(m.Body)))
		}
	}
	return modified
}

// sipURIHostRe 匹配 sip: 或 sips: URI，捕获 scheme、可选 userinfo、host
var sipURIHostRe = regexp.MustCompile(`(?i)(sips?://|sips?:)(?:([^@>;,\s"']+)@)?([^:>;,\s"']+)`)

// RewriteRoutingHeaders 将 Contact / Record-Route 头中的内网 IP 主机改写为公网地址，
// 使外部对端的 ACK/BYE 等对话内请求能正确路由回中继服务器。
// 仅当 host 是内网 IP 时改写，域名/公网 IP 保持原样。返回是否修改过
func (m *Message) RewriteRoutingHeaders(publicAddr string) bool {
	modified := false
	for _, name := range []string{"Contact", "Record-Route"} {
		v := m.GetHeader(name)
		if v == "" {
			continue
		}
		nv := rewriteSIPURIHost(v, publicAddr)
		if nv != v {
			m.SetHeader(name, nv)
			modified = true
		}
	}
	return modified
}

// rewriteSIPURIHost 替换头值中所有 sip URI 的内网 host 为 publicAddr
func rewriteSIPURIHost(val, publicAddr string) string {
	return sipURIHostRe.ReplaceAllStringFunc(val, func(m string) string {
		sub := sipURIHostRe.FindStringSubmatch(m)
		if len(sub) < 4 {
			return m
		}
		host := sub[3]
		if ip := net.ParseIP(host); ip == nil || IsPublicIP(host) {
			return m
		}
		if sub[2] == "" {
			return sub[1] + publicAddr
		}
		return sub[1] + sub[2] + "@" + publicAddr
	})
}

// IsPublicIP 判断是否为公网 IP（简化判断）
func IsPublicIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// 私有地址段
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 {
			return false
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return false
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return false
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return false // CGNAT
		}
	}
	return true
}
