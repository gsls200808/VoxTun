package util

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// countingWriter 包装 Writer，把每次成功写出的字节数回调出去（用于流量统计）
type countingWriter struct {
	w io.Writer
	n func(int)
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.n(n)
	}
	return n, err
}

// Join 连接两端，双向拷贝数据，直到一方关闭或出错
func Join(c1, c2 net.Conn) {
	JoinCounted(c1, c2, nil, nil)
}

// JoinCounted 同 Join，额外回调两个方向的字节数。
// count12 统计 c1 -> c2 的字节数，count21 统计 c2 -> c1 的字节数，为 nil 时忽略。
func JoinCounted(c1, c2 net.Conn, count12, count21 func(int)) {
	if count12 == nil {
		count12 = func(int) {}
	}
	if count21 == nil {
		count21 = func(int) {}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countingWriter{w: c2, n: count12}, c1)
		// 关闭写端，让对端感知 EOF
		if tc, ok := c2.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(countingWriter{w: c1, n: count21}, c2)
		if tc, ok := c1.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// SetKeepAlive 设置 TCP keepalive
func SetKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// ReadAll 读取连接所有数据直到关闭
func ReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

// ParseAddr 解析 host:port
func ParseAddr(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
