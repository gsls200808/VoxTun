package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ipGeoHTTP 归属地查询用的全局客户端，超时收紧避免拖慢面板请求
var ipGeoHTTP = &http.Client{Timeout: 5 * time.Second}

// 上游接口地址，定义为变量便于测试替换
var (
	pconlineURL = "https://whois.pconline.com.cn/ipJson.jsp"
	ipapiURL    = "http://ip-api.com/json/"
)

// ipGeoText 查询公网 IP 的归属地展示文本（如 "辽宁 沈阳市 China Mobile"）。
// 每次调用实时查询上游，无缓存无本地库；主源 ip-api.com（lang=zh-CN，中文省市，
// 运营商为英文全称），失败时回退 pconline（中文省市+中文运营商，GBK 编码）。
func ipGeoText(ctx context.Context, ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("invalid ip")
	}
	// 内网/保留地址不查上游，直接短路
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return "内网地址", nil
	}
	if text, err := ipGeoIPAPI(ctx, ip); err == nil {
		return text, nil
	}
	return ipGeoPconline(ctx, ip)
}

// ---------------- 备源：太平洋电脑网（GBK 编码 JSON，中文运营商） ----------------

type pconlineResp struct {
	Pro  string `json:"pro"`
	City string `json:"city"`
	Addr string `json:"addr"` // 一般为 "辽宁省沈阳市 联通" 形式的完整归属地
	Err  string `json:"err"`
}

func ipGeoPconline(ctx context.Context, ip net.IP) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		pconlineURL+"?ip="+ip.String()+"&json=true", nil)
	if err != nil {
		return "", err
	}
	resp, err := ipGeoHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pconline http %d", resp.StatusCode)
	}
	// 响应为 GBK 编码，需转码后解析
	body, err := io.ReadAll(transform.NewReader(resp.Body, simplifiedchinese.GBK.NewDecoder()))
	if err != nil {
		return "", err
	}
	var d pconlineResp
	if err := json.Unmarshal(body, &d); err != nil {
		return "", err
	}
	if text := strings.TrimSpace(d.Addr); text != "" {
		return text, nil
	}
	// addr 为空时退化为省市拼接（如国外 IP）
	if text := strings.TrimSpace(strings.TrimSpace(d.Pro) + " " + strings.TrimSpace(d.City)); text != "" {
		return text, nil
	}
	return "", fmt.Errorf("pconline empty result (err=%s)", d.Err)
}

// ---------------- 主源：ip-api.com（免费版仅 HTTP，lang=zh-CN，45 次/分） ----------------

type ipapiResp struct {
	Status     string `json:"status"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
	ISP        string `json:"isp"`
}

func ipGeoIPAPI(ctx context.Context, ip net.IP) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		ipapiURL+ip.String()+"?lang=zh-CN&fields=status,regionName,city,isp", nil)
	if err != nil {
		return "", err
	}
	resp, err := ipGeoHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ip-api http %d", resp.StatusCode)
	}
	var d ipapiResp
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", err
	}
	if d.Status != "success" {
		return "", fmt.Errorf("ip-api status %s", d.Status)
	}
	parts := make([]string, 0, 3)
	if s := strings.TrimSpace(d.RegionName); s != "" {
		parts = append(parts, s)
	}
	if s := strings.TrimSpace(d.City); s != "" && s != strings.TrimSpace(d.RegionName) {
		parts = append(parts, s)
	}
	if s := strings.TrimSpace(d.ISP); s != "" {
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("ip-api empty result")
	}
	return strings.Join(parts, " "), nil
}

// handleIPGeo GET /api/ipgeo?ip=x.x.x.x 实时查询 IP 归属地。
// 返回 {"ip":"...","text":"辽宁省沈阳市 联通"}；查询失败时 text 为空（前端静默不显示），
// 内网地址返回 "内网地址"。查询量极小（面板展示客户端时才调用），无缓存。
func (s *Server) handleIPGeo(rw http.ResponseWriter, r *http.Request) {
	ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "invalid ip"})
		return
	}
	text, err := ipGeoText(r.Context(), ip)
	if err != nil {
		writeJSON(rw, http.StatusOK, map[string]string{"ip": ipStr, "text": ""})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]string{"ip": ipStr, "text": text})
}
