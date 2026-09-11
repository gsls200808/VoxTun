package server

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"

	"voxTun/internal/app/common/util"
)

// certReloader 按需加载 TLS 证书，并在证书文件更新后自动重新加载。
// 这样 acme.sh 等工具续期后无需重启 voxsrv（重启会断开隧道）即可生效。
type certReloader struct {
	certFile string
	keyFile  string

	mu      sync.RWMutex
	cert    *tls.Certificate
	modTime int64
}

// newCertReloader 创建加载器并做一次初始加载，失败则返回错误（启动阶段快速失败）
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload 重新读取证书文件，仅在加载成功时更新缓存
func (r *certReloader) reload() error {
	info, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("stat cert %s: %w", r.certFile, err)
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load tls cert: %w", err)
	}
	r.mu.Lock()
	r.cert = &cert
	r.modTime = info.ModTime().UnixNano()
	r.mu.Unlock()
	return nil
}

// getCertificate 实现 tls.Config.GetCertificate：证书文件更新后自动重载
func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if info, err := os.Stat(r.certFile); err == nil {
		r.mu.RLock()
		stale := info.ModTime().UnixNano() != r.modTime
		r.mu.RUnlock()
		if stale {
			if err := r.reload(); err != nil {
				util.Logger.Warnw("reload tls cert failed, keep previous", "cert", r.certFile, "err", err)
			} else {
				util.Logger.Infow("tls cert reloaded", "cert", r.certFile)
			}
		}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}
