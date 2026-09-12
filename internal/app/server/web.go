package server

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"voxTun/internal/app/common/config"
	"voxTun/internal/app/common/consts"
	"voxTun/internal/app/common/ipfilter"
	"voxTun/internal/app/common/util"
)

// webAssets 面板前端静态资源（petite-vue + 页面），随二进制一起分发
//
//go:embed web
var webAssets embed.FS

const (
	// sessionCookie 面板会话 Cookie 名
	sessionCookie = "voxtun_session"
	// sessionTTL 会话有效期
	sessionTTL = 24 * time.Hour
	// maxBodySize 请求体上限，面板接口载荷很小
	maxBodySize = 4 << 10
)

// webServer 管理面板 HTTP 服务
type webServer struct {
	cfg     config.WebServerConfig
	httpSrv *http.Server

	sessMu   sync.Mutex
	sessions map[string]time.Time // token -> 过期时间
}

// newWebServer 构建面板服务（不监听，仅准备路由）
func newWebServer(srv *Server) (*webServer, error) {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		return nil, fmt.Errorf("read embedded web assets: %w", err)
	}
	w := &webServer{
		cfg:      srv.cfg.WebServer,
		sessions: make(map[string]time.Time),
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/login", w.handleLogin)
	mux.HandleFunc("/api/logout", w.handleLogout)
	mux.HandleFunc("/api/overview", w.requireAuth(srv.handleOverview))
	mux.HandleFunc("/api/extensions", w.requireAuth(srv.handleExtensions))
	mux.HandleFunc("/api/proxy/close", w.requireAuth(srv.handleProxyClose))
	mux.HandleFunc("/api/client/close", w.requireAuth(srv.handleClientClose))
	mux.HandleFunc("/api/ipfilter", w.requireAuth(srv.handleIPFilterGet))
	mux.HandleFunc("/api/ipfilter/toggle", w.requireAuth(srv.handleIPFilterToggle))
	mux.HandleFunc("/api/ipfilter/add", w.requireAuth(srv.handleIPFilterAdd))
	mux.HandleFunc("/api/ipfilter/remove", w.requireAuth(srv.handleIPFilterRemove))
	mux.HandleFunc("/api/ipfilter/check", w.requireAuth(srv.handleIPFilterCheck))
	w.httpSrv = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", w.cfg.Addr, w.cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return w, nil
}

// startWebServer 启动管理面板；未配置 webServer.port 时不启动
func (s *Server) startWebServer() error {
	if !s.cfg.WebServer.Enabled() {
		return nil
	}
	if s.cfg.WebServer.User == "" || s.cfg.WebServer.Password == "" {
		return fmt.Errorf("webServer.user and webServer.password must be set when webServer.port is configured")
	}
	if s.cfg.WebServer.Addr == "" {
		s.cfg.WebServer.Addr = "0.0.0.0"
	}
	w, err := newWebServer(s)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", w.httpSrv.Addr)
	if err != nil {
		return fmt.Errorf("listen dashboard %s: %w", w.httpSrv.Addr, err)
	}
	s.web = w
	go func() {
		util.Logger.Infow("dashboard listening", "addr", ln.Addr().String(), "user", w.cfg.User)
		if err := w.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			util.Logger.Errorw("dashboard serve", "err", err)
		}
	}()
	return nil
}

// ---------------- 会话认证 ----------------

func (w *webServer) validSession(r *http.Request) bool {
	ck, err := r.Cookie(sessionCookie)
	if err != nil || ck.Value == "" {
		return false
	}
	w.sessMu.Lock()
	defer w.sessMu.Unlock()
	exp, ok := w.sessions[ck.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(w.sessions, ck.Value)
		return false
	}
	return true
}

// requireAuth 包一层会话校验，未登录返回 401
func (w *webServer) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !w.validSession(r) {
			writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": "未登录或会话已过期"})
			return
		}
		h(rw, r)
	}
}

func (w *webServer) handleLogin(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBodySize)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	// 恒定时间比较，避免从响应耗时上推断用户名/密码
	userOK := subtle.ConstantTimeCompare([]byte(req.User), []byte(w.cfg.User)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(req.Password), []byte(w.cfg.Password)) == 1
	if !userOK || !passOK {
		util.Logger.Warnw("dashboard login failed", "remote", r.RemoteAddr, "user", req.User)
		writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": "用户名或密码错误"})
		return
	}

	token, err := newSessionToken()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "生成会话失败"})
		return
	}
	now := time.Now()
	w.sessMu.Lock()
	for t, exp := range w.sessions { // 顺手清理过期会话
		if now.After(exp) {
			delete(w.sessions, t)
		}
	}
	w.sessions[token] = now.Add(sessionTTL)
	w.sessMu.Unlock()

	http.SetCookie(rw, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
	util.Logger.Infow("dashboard login ok", "remote", r.RemoteAddr, "user", req.User)
	writeJSON(rw, http.StatusOK, map[string]interface{}{"ok": true})
}

func (w *webServer) handleLogout(rw http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		w.sessMu.Lock()
		delete(w.sessions, ck.Value)
		w.sessMu.Unlock()
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	writeJSON(rw, http.StatusOK, map[string]interface{}{"ok": true})
}

func newSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ---------------- 面板数据 ----------------

// serverView 服务端概览
type serverView struct {
	Version     string `json:"version"`
	StartAt     int64  `json:"startAt"`
	Uptime      int64  `json:"uptime"`
	BindAddr    string `json:"bindAddr"`
	BindPort    int    `json:"bindPort"`
	PublicAddr  string `json:"publicAddr"`
	ProxyCount  int    `json:"proxyCount"`
	ClientCount int    `json:"clientCount"`
	BytesIn     int64  `json:"bytesIn"`
	BytesOut    int64  `json:"bytesOut"`
}

// proxyView 单个代理的运行状态
type proxyView struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	LocalIP    string `json:"localIP"`
	LocalPort  int    `json:"localPort"`
	RemotePort int    `json:"remotePort"`
	RewriteSDP bool   `json:"rewriteSDP"`
	ClientAddr string `json:"clientAddr"`
	Conns      int64  `json:"conns"`
	BytesIn    int64  `json:"bytesIn"`
	BytesOut   int64  `json:"bytesOut"`
	StartAt    int64  `json:"startAt"`
}

// clientView 单个客户端连接
type clientView struct {
	Addr       string `json:"addr"`
	Authed     bool   `json:"authed"`
	ProxyCount int    `json:"proxyCount"`
	StartAt    int64  `json:"startAt"`
	LastPing   int64  `json:"lastPing"`
}

type overviewResp struct {
	Server  serverView   `json:"server"`
	Proxies []proxyView  `json:"proxies"`
	Clients []clientView `json:"clients"`
}

func (s *Server) handleOverview(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, http.StatusOK, s.snapshot())
}

// handleExtensions 返回分机号流量分析结果（列表始终为数组，避免前端拿到 null）
func (s *Server) handleExtensions(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]interface{}{"extensions": s.extStats.snapshot()})
}

func (s *Server) handleProxyClose(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBodySize)).Decode(&req); err != nil || req.Name == "" {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "缺少代理名称"})
		return
	}
	if err := s.CloseProxyByName(req.Name); err != nil {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *Server) handleClientClose(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBodySize)).Decode(&req); err != nil || req.Addr == "" {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "缺少客户端地址"})
		return
	}
	if err := s.CloseClientByAddr(req.Addr); err != nil {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]interface{}{"ok": true})
}

// snapshot 汇总当前服务端状态，供面板展示
func (s *Server) snapshot() overviewResp {
	out := overviewResp{Proxies: []proxyView{}, Clients: []clientView{}}

	s.proxiesMu.RLock()
	proxies := make([]*ProxyInfo, 0, len(s.proxies))
	for _, p := range s.proxies {
		proxies = append(proxies, p)
	}
	s.proxiesMu.RUnlock()

	for _, p := range proxies {
		pv := proxyView{
			Name:       p.name,
			Type:       p.origType,
			LocalIP:    p.localIP,
			LocalPort:  p.localPort,
			RemotePort: p.remotePort,
			RewriteSDP: p.rewriteSDP,
			ClientAddr: p.client.conn.RemoteAddr().String(),
			Conns:      p.connCount(),
			BytesIn:    p.stats.bytesIn.Load(),
			BytesOut:   p.stats.bytesOut.Load(),
			StartAt:    p.startAt.Unix(),
		}
		out.Server.BytesIn += pv.BytesIn
		out.Server.BytesOut += pv.BytesOut
		out.Proxies = append(out.Proxies, pv)
	}
	sort.Slice(out.Proxies, func(i, j int) bool { return out.Proxies[i].Name < out.Proxies[j].Name })

	s.clientsMu.RLock()
	for _, c := range s.clients {
		c.proxiesMu.RLock()
		n := len(c.proxies)
		c.proxiesMu.RUnlock()
		c.pingMu.Lock()
		last := c.lastPing
		c.pingMu.Unlock()
		out.Clients = append(out.Clients, clientView{
			Addr:       c.conn.RemoteAddr().String(),
			Authed:     c.authed,
			ProxyCount: n,
			StartAt:    c.startAt.Unix(),
			LastPing:   last.Unix(),
		})
	}
	s.clientsMu.RUnlock()
	sort.Slice(out.Clients, func(i, j int) bool { return out.Clients[i].Addr < out.Clients[j].Addr })

	out.Server.Version = consts.Version
	out.Server.StartAt = s.startAt.Unix()
	out.Server.Uptime = int64(time.Since(s.startAt).Seconds())
	out.Server.BindAddr = s.cfg.BindAddr
	out.Server.BindPort = s.cfg.BindPort
	out.Server.PublicAddr = s.cfg.PublicAddr
	out.Server.ProxyCount = len(out.Proxies)
	out.Server.ClientCount = len(out.Clients)
	return out
}

// ---------------- 面板操作 ----------------

// CloseProxyByName 关闭指定名称的代理（面板操作用）。
// 仅停止服务端的公网监听并注销；客户端若重连仍会重新注册该代理。
func (s *Server) CloseProxyByName(name string) error {
	for _, c := range s.clientSessions() {
		if c.closeProxy(name) {
			util.Logger.Infow("proxy closed by dashboard", "name", name, "client", c.conn.RemoteAddr().String())
			return nil
		}
	}
	return fmt.Errorf("代理 %s 不存在", name)
}

// CloseClientByAddr 断开指定地址的客户端控制连接（面板操作用）
func (s *Server) CloseClientByAddr(addr string) error {
	s.clientsMu.RLock()
	c := s.clients[addr]
	s.clientsMu.RUnlock()
	if c == nil {
		return fmt.Errorf("客户端 %s 不存在", addr)
	}
	util.Logger.Infow("client closed by dashboard", "addr", addr)
	c.Close()
	return nil
}

// clientSessions 返回当前所有客户端会话的快照
func (s *Server) clientSessions() []*ClientSession {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()
	out := make([]*ClientSession, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out
}

// ---------------- IP 黑白名单 ----------------

// ipFilterView 面板展示用的黑白名单数据
type ipFilterView struct {
	Enable    bool     `json:"enable"`
	AllowList []string `json:"allowList"`
	DenyList  []string `json:"denyList"`
}

// ipFilterView 读取当前生效的黑白名单（列表始终为数组，避免前端拿到 null）
func (s *Server) ipFilterView() ipFilterView {
	f := s.currentIPFilter()
	return ipFilterView{
		Enable:    f.Enable,
		AllowList: append([]string{}, f.AllowList...),
		DenyList:  append([]string{}, f.DenyList...),
	}
}

// currentIPFilter 返回当前生效的黑白名单配置
func (s *Server) currentIPFilter() config.IPFilterConfig {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	return s.cfg.IPFilter
}

// mutateIPFilter 在锁内修改黑白名单，依次完成「校验 → 回写配置文件 → 运行期生效」。
// 任一步失败都返回错误，当前生效的名单与磁盘配置保持原样。
func (s *Server) mutateIPFilter(mutate func(*config.IPFilterConfig) error) error {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()

	next := config.IPFilterConfig{
		Enable:    s.cfg.IPFilter.Enable,
		AllowList: append([]string{}, s.cfg.IPFilter.AllowList...),
		DenyList:  append([]string{}, s.cfg.IPFilter.DenyList...),
	}
	if err := mutate(&next); err != nil {
		return err
	}
	if err := ipfilter.Validate(next); err != nil {
		return err
	}
	if s.configPath == "" {
		return fmt.Errorf("未指定配置文件路径，无法回写配置")
	}
	if err := config.SaveIPFilter(s.configPath, next); err != nil {
		return fmt.Errorf("回写配置失败: %w", err)
	}
	if err := s.ipFilter.Reload(next); err != nil {
		return err
	}
	s.cfg.IPFilter = next
	util.Logger.Infow("ip filter updated by dashboard",
		"enable", next.Enable, "allow", len(next.AllowList), "deny", len(next.DenyList))
	return nil
}

// pickList 取 allow/deny 对应的名单字段
func pickList(f *config.IPFilterConfig, name string) (*[]string, error) {
	switch name {
	case "allow":
		return &f.AllowList, nil
	case "deny":
		return &f.DenyList, nil
	default:
		return nil, fmt.Errorf("未知的名单类型 %q", name)
	}
}

func (s *Server) handleIPFilterGet(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(rw, http.StatusOK, s.ipFilterView())
}

func (s *Server) handleIPFilterToggle(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBodySize)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	err := s.mutateIPFilter(func(f *config.IPFilterConfig) error {
		f.Enable = req.Enable
		return nil
	})
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, s.ipFilterView())
}

func (s *Server) handleIPFilterAdd(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		List string `json:"list"` // allow / deny
		IP   string `json:"ip"`   // 单个 IP 或 CIDR
		Mask int    `json:"mask"` // 0/32 按 IP 添加，24/16 等按掩码添加
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBodySize)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	entry, err := normalizeIPEntry(req.IP, req.Mask)
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	err = s.mutateIPFilter(func(f *config.IPFilterConfig) error {
		list, err := pickList(f, req.List)
		if err != nil {
			return err
		}
		for _, it := range *list { // 已存在则视为成功，避免重复条目
			if it == entry {
				return nil
			}
		}
		*list = append(*list, entry)
		return nil
	})
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	util.Logger.Infow("ip filter entry added by dashboard", "list", req.List, "entry", entry)
	writeJSON(rw, http.StatusOK, s.ipFilterView())
}

func (s *Server) handleIPFilterRemove(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		List  string `json:"list"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBodySize)).Decode(&req); err != nil || req.Value == "" {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "缺少要删除的条目"})
		return
	}
	err := s.mutateIPFilter(func(f *config.IPFilterConfig) error {
		list, err := pickList(f, req.List)
		if err != nil {
			return err
		}
		kept := make([]string, 0, len(*list))
		for _, it := range *list {
			if it != req.Value {
				kept = append(kept, it)
			}
		}
		*list = kept
		return nil
	})
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	util.Logger.Infow("ip filter entry removed by dashboard", "list", req.List, "entry", req.Value)
	writeJSON(rw, http.StatusOK, s.ipFilterView())
}

func (s *Server) handleIPFilterCheck(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, maxBodySize)).Decode(&req); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "不是合法的 IP 地址"})
		return
	}
	writeJSON(rw, http.StatusOK, s.ipFilter.Check(ip))
}

// normalizeIPEntry 规范化面板提交的条目。
// mask 为 0 或 32 时按单个 IP/CIDR 处理；其余按掩码处理，如 192.168.1.5 + /24 → 192.168.1.0/24。
func normalizeIPEntry(value string, mask int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("请填写 IP 地址")
	}
	if mask != 0 && mask != 32 {
		if mask < 0 || mask > 32 {
			return "", fmt.Errorf("无效的掩码 /%d", mask)
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return "", fmt.Errorf("按掩码添加时 %q 不是合法的 IP 地址", value)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return "", fmt.Errorf("按掩码添加仅支持 IPv4 地址")
		}
		mask4 := net.CIDRMask(mask, 32)
		// IPNet.String() 不会自动抹掉主机位，需先按掩码取网络号
		return (&net.IPNet{IP: ip4.Mask(mask4), Mask: mask4}).String(), nil
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if _, n, err := net.ParseCIDR(value); err == nil {
		return n.String(), nil
	}
	return "", fmt.Errorf("%q 不是合法的 IP 或 CIDR", value)
}

func writeJSON(rw http.ResponseWriter, code int, v interface{}) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}
