package server

import "sync/atomic"

// proxyStats 代理运行期统计。
// 计数作用在数据转发热路径上，全部使用原子操作，不引入锁开销。
// RTP 中继的媒体流量也计入其所属代理（见 getOrCreateRTPRelays）。
type proxyStats struct {
	bytesIn     atomic.Int64 // 外部 -> 内网 累计字节数
	bytesOut    atomic.Int64 // 内网 -> 外部 累计字节数
	activeConns atomic.Int64 // 当前活动 TCP 连接数（UDP 代理按外部对端数另行统计）
}

func (s *proxyStats) addIn(n int) {
	if n > 0 {
		s.bytesIn.Add(int64(n))
	}
}

func (s *proxyStats) addOut(n int) {
	if n > 0 {
		s.bytesOut.Add(int64(n))
	}
}
