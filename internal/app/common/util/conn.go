package util

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Join 连接两端，双向拷贝数据，直到一方关闭或出错
func Join(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c2, c1)
		// 关闭写端，让对端感知 EOF
		if tc, ok := c2.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c1, c2)
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
