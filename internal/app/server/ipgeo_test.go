package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubGeoUpstreams 把两个上游替换为 httptest 服务，返回恢复函数
func stubGeoUpstreams(t *testing.T, pconline, ipapi *httptest.Server) {
	t.Helper()
	oldP, oldI := pconlineURL, ipapiURL
	pconlineURL, ipapiURL = pconline.URL+"/ipJson.jsp", ipapi.URL+"/json/"
	t.Cleanup(func() { pconlineURL, ipapiURL = oldP, oldI })
}

func TestIPGeoPrimary(t *testing.T) {
	pc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("主源成功时不应回退到 pconline")
	}))
	defer pc.Close()
	ia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","regionName":"辽宁","city":"沈阳市","isp":"China Mobile"}`))
	}))
	defer ia.Close()
	stubGeoUpstreams(t, pc, ia)

	text, err := ipGeoText(context.Background(), net.ParseIP("1.2.3.4"))
	if err != nil {
		t.Fatalf("ipGeoText: %v", err)
	}
	if text != "辽宁 沈阳市 China Mobile" {
		t.Fatalf("主源归属地文本错误: %q", text)
	}
}

func TestIPGeoFallbackPconlineGBK(t *testing.T) {
	// 主源 ip-api 失败时回退 pconline；pconline 响应是 GBK 编码：「辽宁省沈阳市 联通」的 GBK 字节
	gbkJSON := []byte("{\"ip\":\"1.2.3.4\",\"pro\":\"\xc1\xc9\xc4\xfe\xca\xa1\",\"city\":\"\xc9\xf2\xd1\xf4\xca\xd0\",\"addr\":\"\xc1\xc9\xc4\xfe\xca\xa1\xc9\xf2\xd1\xf4\xca\xd0 \xc1\xaa\xcd\xa8\",\"err\":\"\"}")
	pc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=gbk")
		_, _ = w.Write(gbkJSON)
	}))
	defer pc.Close()
	ia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ia.Close()
	stubGeoUpstreams(t, pc, ia)

	text, err := ipGeoText(context.Background(), net.ParseIP("1.2.3.4"))
	if err != nil {
		t.Fatalf("ipGeoText: %v", err)
	}
	if text != "辽宁省沈阳市 联通" {
		t.Fatalf("备源归属地文本错误: %q", text)
	}
}

func TestIPGeoPrivate(t *testing.T) {
	pc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("内网地址不应查询上游")
	}))
	defer pc.Close()
	stubGeoUpstreams(t, pc, pc)

	text, err := ipGeoText(context.Background(), net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("ipGeoText: %v", err)
	}
	if text != "内网地址" {
		t.Fatalf("内网地址应短路返回，实得 %q", text)
	}
}

func TestIPGeoBothFail(t *testing.T) {
	pc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer pc.Close()
	stubGeoUpstreams(t, pc, pc)

	if _, err := ipGeoText(context.Background(), net.ParseIP("1.2.3.4")); err == nil {
		t.Fatal("双源均失败时应返回错误")
	}
}
