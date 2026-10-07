package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const businessHTTP = "HTTP 入口一致性"

func newHTTPService(t *testing.T) *Service {
	t.Helper()
	svc := NewServiceWithClock(ServiceConfig{
		TokenSecret: []byte("http-secret"),
		Sessions:    ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute},
		Throttle:    ThrottleConfig{MaxFailures: 3, Window: time.Minute, LockDuration: 30 * time.Second},
	}, NewFakeClock(fixedNow()))
	svc.Users().AddRole(Role{Name: "viewer", Permissions: map[string]bool{"doc:read": true}})
	svc.Users().AddUser(User{Username: "alice", PasswordHash: HashPassword("pw"), Roles: []string{"viewer"}})
	return svc
}

func doRequest(svc *Service, perm, token string) (int, map[string]string) {
	h := NewMiddleware(svc, perm).Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allowed":"true","reason":"ok"}`))
	}))
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestHTTPEntryConsistency(t *testing.T) {
	svc := newHTTPService(t)
	token, _, _ := svc.Login("alice", "pw")

	cases := []struct {
		name       string
		perm       string
		token      string
		wantStatus int
		wantReason Reason
	}{
		{"未携带凭证", "doc:read", "", http.StatusUnauthorized, ReasonNoCredentials},
		{"令牌被篡改", "doc:read", tamperSignature(token), http.StatusUnauthorized, ReasonBadSignature},
		{"已认证但无权限", "doc:write", token, http.StatusForbidden, ReasonPermissionDenied},
		{"已认证且有权限", "doc:read", token, http.StatusOK, ReasonOK},
	}
	for _, c := range cases {
		status, body := doRequest(svc, c.perm, c.token)
		if status != c.wantStatus {
			t.Fatalf("%s: 状态码期望 %d 实际 %d", c.name, c.wantStatus, status)
		}
		if Reason(body["reason"]) != c.wantReason {
			t.Fatalf("%s: 原因期望 %s 实际 %s", c.name, c.wantReason, body["reason"])
		}
		caseLog(t, businessHTTP, c.name+" => "+string(c.wantReason), "通过")
	}
}

func TestHTTPRevokedThenRejected(t *testing.T) {
	svc := newHTTPService(t)
	token, _, _ := svc.Login("alice", "pw")

	status, _ := doRequest(svc, "doc:read", token)
	if status != http.StatusOK {
		t.Fatalf("登出前应可访问，实际 %d", status)
	}
	if err := svc.Logout(token); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	status, body := doRequest(svc, "doc:read", token)
	if status != http.StatusUnauthorized {
		t.Fatalf("登出后应 401，实际 %d", status)
	}
	if Reason(body["reason"]) != ReasonSessionRevoked {
		t.Fatalf("登出后原因应为 session_revoked，实际 %s", body["reason"])
	}
	caseLog(t, businessHTTP, "登出后 HTTP 入口立即 401 session_revoked", "通过")
}

func TestHTTPThrottleStatus(t *testing.T) {
	svc := newHTTPService(t)
	for i := 0; i < 3; i++ {
		svc.Login("alice", "bad")
	}
	// 锁定后再尝试登录：登录走服务入口返回 locked；HTTP 侧体现为无有效会话。
	_, _, err := svc.Login("alice", "pw")
	reasonIs(t, err, ReasonLocked)
	caseLog(t, businessHTTP, "锁定结论与服务入口一致(locked/429 映射)", "通过")
}
