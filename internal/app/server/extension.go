package server

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"voxTun/internal/app/protocol/iax"
	"voxTun/internal/app/protocol/sip"
)

// 分机号流量分析
//
// 在转发热路径上旁路解析经过隧道的 SIP / IAX 信令，按分机号汇总：
// 最后注册时间、最后接通时间、接通次数、累计通话时长与收发字节。
// 只读取报文、不改写也不报错，解析失败一律静默忽略，不影响隧道功能。
//
// 只统计注册过的分机：记录只在 SIP REGISTER / IAX REGREQ 时建立；
// 呼叫中出现但从未注册的号码（外线被叫、中继号等）不会进入列表，
// 通话与媒体字节也只归因给参与呼叫的已注册分机。
//
// 「接通」口径：SIP 取 INVITE 的 200 OK / ACK，IAX 取 ACCEPT；
// 通话时长从接通算到 BYE / HANGUP，未接通的呼叫不计入次数与时长。

const (
	// maxExtDigits 分机号最大位数。更长的 user 部分（E.164 外线号码、中继号）不计入统计
	maxExtDigits = 8
	// maxExtPeers 对端地址索引上限。超过后整体重建，避免长期运行时 NAT 端口漂移导致索引无限增长
	maxExtPeers = 4096
	// maxExtCalls 呼叫表上限。超过后淘汰最早的条目，避免未正常结束的呼叫长期占用内存
	maxExtCalls = 1024

	// IAX2 信息元素（IE）类型（RFC 5456）
	iaxIECalledNumber  = 1
	iaxIECallingNumber = 2
)

// extRecord 一个分机的统计记录
type extRecord struct {
	number       string
	protocol     string // sip / iax
	peer         string // 最近一次注册的来源地址
	lastRegister time.Time
	lastAnswer   time.Time
	calls        int64
	callSeconds  int64
	bytesIn      int64
	bytesOut     int64
}

// extCall 一次呼叫；started 为零值表示尚未接通（如振铃中）
type extCall struct {
	keys    []string // 参与该呼叫的分机记录键
	started time.Time
	seen    time.Time
}

// extTracker 分机号流量分析器
type extTracker struct {
	mu    sync.RWMutex
	exts  map[string]*extRecord // 键: 协议/分机号
	peers map[string]string     // 对端地址 -> 分机记录键，用于按来源地址归因字节
	calls map[string]*extCall   // 呼叫键 -> 呼叫（SIP 用 Call-ID，IAX 用对端地址）
}

func newExtTracker() *extTracker {
	return &extTracker{
		exts:  make(map[string]*extRecord),
		peers: make(map[string]string),
		calls: make(map[string]*extCall),
	}
}

// extKey 分机记录的唯一键：协议 + 分机号（同一分机号走 SIP 与 IAX 分别统计）
func extKey(protocol, number string) string {
	return protocol + "/" + number
}

// recordLocked 取（必要时创建）分机记录，调用方需持写锁
func (t *extTracker) recordLocked(key, protocol, number, peer string) *extRecord {
	r, ok := t.exts[key]
	if !ok {
		r = &extRecord{number: number, protocol: protocol}
		t.exts[key] = r
	}
	if peer != "" {
		r.peer = peer
		if len(t.peers) >= maxExtPeers {
			// 索引过大时整体重建：只是统计归因的近似信息，重建后可重新学习
			t.peers = make(map[string]string)
		}
		t.peers[peer] = key
	}
	return r
}

// markRegister 记录一次注册（SIP REGISTER、IAX REGREQ），并把来源地址绑定到该分机
func (t *extTracker) markRegister(protocol, number, peer string) {
	if number == "" {
		return
	}
	key := extKey(protocol, number)
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.recordLocked(key, protocol, number, peer)
	r.lastRegister = time.Now()
}

// pendCall 记录一次呼叫中已注册分机的参与情况（尚未接通）。
// 只为已由 markRegister 建立记录的分机登记：未注册号码（外线、中继号等）忽略。
// 一次呼叫没有任何已注册分机参与时不跟踪；callKey 相同的呼叫只登记一次，
// 因此 SIP 的 re-INVITE / 重传不会重置呼叫。
func (t *extTracker) pendCall(protocol, callKey, caller, callee string) {
	if callKey == "" || (caller == "" && callee == "") {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.calls[callKey]; ok {
		return
	}
	keys := make([]string, 0, 2)
	add := func(n string) {
		if n == "" {
			return
		}
		key := extKey(protocol, n)
		if _, ok := t.exts[key]; !ok {
			// 未注册过的号码不建立统计记录，呼叫指标也不归因给它
			return
		}
		for _, k := range keys {
			if k == key {
				return
			}
		}
		keys = append(keys, key)
	}
	add(caller)
	add(callee)
	if len(keys) == 0 {
		return
	}
	t.calls[callKey] = &extCall{keys: keys, seen: now}
	t.pruneCallsLocked()
}

// answerCall 记录呼叫接通：累计接通次数并记下最后接通时间
func (t *extTracker) answerCall(callKey string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.calls[callKey]
	if !ok || !c.started.IsZero() {
		return
	}
	c.started = now
	for _, key := range c.keys {
		if r, ok := t.exts[key]; ok {
			r.calls++
			r.lastAnswer = now
		}
	}
}

// endCall 结束呼叫：按接通时刻累计通话时长，未接通的呼叫只清理状态
func (t *extTracker) endCall(callKey string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.calls[callKey]
	if !ok {
		return
	}
	delete(t.calls, callKey)
	if c.started.IsZero() {
		return
	}
	secs := int64(now.Sub(c.started).Seconds())
	if secs <= 0 {
		return
	}
	for _, key := range c.keys {
		if r, ok := t.exts[key]; ok {
			r.callSeconds += secs
		}
	}
}

// pruneCallsLocked 呼叫表超限时按登记时间淘汰最早的条目，调用方需持写锁
func (t *extTracker) pruneCallsLocked() {
	for len(t.calls) > maxExtCalls {
		oldestKey := ""
		var oldest time.Time
		for k, c := range t.calls {
			if oldestKey == "" || c.seen.Before(oldest) {
				oldestKey, oldest = k, c.seen
			}
		}
		delete(t.calls, oldestKey)
	}
}

// addPeerBytes 按来源地址归因字节数（SIP 信令、IAX 信令与 IAX 媒体都走这条路径）
func (t *extTracker) addPeerBytes(peer string, inbound bool, n int) {
	if n <= 0 || peer == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	key, ok := t.peers[peer]
	if !ok {
		return
	}
	r, ok := t.exts[key]
	if !ok {
		return
	}
	if inbound {
		r.bytesIn += int64(n)
	} else {
		r.bytesOut += int64(n)
	}
}

// addCallBytes 按 Call-ID 归因 SIP 媒体（RTP 中继）字节数
func (t *extTracker) addCallBytes(callID string, inbound bool, n int) {
	if n <= 0 || callID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.calls[callID]
	if !ok {
		return
	}
	for _, key := range c.keys {
		r, ok := t.exts[key]
		if !ok {
			continue
		}
		if inbound {
			r.bytesIn += int64(n)
		} else {
			r.bytesOut += int64(n)
		}
	}
}

// ---------------- SIP / IAX 解析 ----------------

// sipUserRe 匹配 SIP URI 的 user 部分（要求带 @ 主机）
var sipUserRe = regexp.MustCompile(`(?i)sips?:([^@>;,\s"']+)@`)

// sipNumber 从 From / To 等头值中取出分机号，取不到或不像分机号时返回空串
func sipNumber(headerValue string) string {
	if headerValue == "" {
		return ""
	}
	m := sipUserRe.FindStringSubmatch(headerValue)
	if len(m) < 2 {
		return ""
	}
	return extensionNumber(m[1])
}

// extensionNumber 过滤出像分机号的 user 部分：仅数字与 * #，且长度不超过 maxExtDigits。
// 外线号码（11 位手机号、带国家码的中继号）会被过滤掉，避免污染分机列表。
func extensionNumber(user string) string {
	if user == "" || len(user) > maxExtDigits {
		return ""
	}
	for i := 0; i < len(user); i++ {
		c := user[i]
		if (c < '0' || c > '9') && c != '*' && c != '#' {
			return ""
		}
	}
	return user
}

// observeSIP 解析一条 SIP 报文（出入两个方向都调用），更新分机号统计
func (t *extTracker) observeSIP(data []byte, peer string) {
	if !sip.IsSIP(data) {
		return
	}
	msg := sip.Parse(data)
	if msg == nil {
		return
	}
	callID := msg.GetHeader("Call-ID")
	if msg.IsRequest {
		switch msg.Method {
		case "REGISTER":
			t.markRegister("sip", firstNumber(msg.GetHeader("To"), msg.GetHeader("From")), peer)
		case "INVITE":
			from := sipNumber(msg.GetHeader("From"))
			to := sipNumber(msg.GetHeader("To"))
			t.pendCall("sip", callID, from, to)
		case "ACK":
			t.answerCall(callID)
		case "BYE", "CANCEL":
			t.endCall(callID)
		}
		return
	}
	status, _ := strconv.Atoi(msg.StatusCode)
	cseq := strings.ToUpper(msg.GetHeader("CSeq"))
	switch {
	case strings.Contains(cseq, "INVITE"):
		// 200 OK 表示被叫已接听；其余 >=300 的终态响应表示呼叫失败
		if status == 200 {
			t.pendCall("sip", callID, sipNumber(msg.GetHeader("From")), sipNumber(msg.GetHeader("To")))
			t.answerCall(callID)
		} else if status >= 300 {
			t.endCall(callID)
		}
	case strings.Contains(cseq, "REGISTER"):
		if status == 200 {
			t.markRegister("sip", firstNumber(msg.GetHeader("To"), msg.GetHeader("From")), peer)
		}
	case strings.Contains(cseq, "BYE"):
		t.endCall(callID)
	}
}

// firstNumber 返回第一个非空的分机号
func firstNumber(values ...string) string {
	for _, v := range values {
		if n := sipNumber(v); n != "" {
			return n
		}
	}
	return ""
}

// parseIAXIEs 解析 IAX 帧载荷中的信息元素：类型 1 字节 + 长度 1 字节 + 数据
func parseIAXIEs(data []byte) map[byte]string {
	ies := make(map[byte]string, 2)
	for i := 0; i+2 <= len(data); {
		typ := data[i]
		length := int(data[i+1])
		if i+2+length > len(data) {
			break
		}
		ies[typ] = strings.TrimRight(string(data[i+2:i+2+length]), "\x00")
		i += 2 + length
	}
	return ies
}

// observeIAX 解析一条 IAX 帧（出入两个方向都调用），更新分机号统计。
// IAX 收发两个方向的呼叫编号各自独立，因此呼叫键用对端地址（一个对端通常就是一部话机）。
func (t *extTracker) observeIAX(data []byte, peer string) {
	f := iax.Parse(data)
	if f == nil || !f.IsFull || f.FrameType != iax.FrameTypeIAXControl {
		return
	}
	switch f.SubClass {
	case iax.IAXCommandRegReq:
		ies := parseIAXIEs(f.Data)
		t.markRegister("iax", extensionNumber(ies[iaxIECalledNumber]), peer)
	case iax.IAXCommandNew:
		ies := parseIAXIEs(f.Data)
		// 同一对端上出现新的 NEW，说明上一次呼叫已结束
		t.endCall(peer)
		t.pendCall("iax", peer,
			extensionNumber(ies[iaxIECallingNumber]), extensionNumber(ies[iaxIECalledNumber]))
	case iax.IAXCommandAccept:
		t.answerCall(peer)
	case iax.IAXCommandHangup, iax.IAXCommandReject:
		t.endCall(peer)
	}
}

// ---------------- 面板数据 ----------------

// extView 面板展示用的分机统计
type extView struct {
	Number       string `json:"number"`
	Protocol     string `json:"protocol"`
	Peer         string `json:"peer"`
	LastRegister int64  `json:"lastRegister"`
	LastAnswer   int64  `json:"lastAnswer"`
	Calls        int64  `json:"calls"`
	CallSeconds  int64  `json:"callSeconds"`
	BytesIn      int64  `json:"bytesIn"`
	BytesOut     int64  `json:"bytesOut"`
}

// active 最后活跃时间（注册或接通），用于列表排序
func (v extView) active() int64 {
	if v.LastAnswer > v.LastRegister {
		return v.LastAnswer
	}
	return v.LastRegister
}

// snapshot 返回全部分机记录，按最后活跃时间倒序
func (t *extTracker) snapshot() []extView {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]extView, 0, len(t.exts))
	for _, r := range t.exts {
		out = append(out, extView{
			Number:       r.number,
			Protocol:     r.protocol,
			Peer:         r.peer,
			LastRegister: unixOrZero(r.lastRegister),
			LastAnswer:   unixOrZero(r.lastAnswer),
			Calls:        r.calls,
			CallSeconds:  r.callSeconds,
			BytesIn:      r.bytesIn,
			BytesOut:     r.bytesOut,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].active(), out[j].active()
		if ai != aj {
			return ai > aj
		}
		if out[i].Number != out[j].Number {
			return out[i].Number < out[j].Number
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
