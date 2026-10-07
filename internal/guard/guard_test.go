package guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/feng111627/session-auth-guard-go/internal/auth"
)

type fixture struct {
	svc   *auth.Service
	clock *auth.FixedClock
	users *auth.UserStore
	login func(u, p string) string
}

func buildFixture(t *testing.T) fixture {
	t.Helper()
	clock := &auth.FixedClock{T: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	users := auth.NewUserStore()
	users.AddUser(&auth.User{ID: "u1", Username: "alice", PasswordHash: auth.HashPassword("pw"), Roles: []string{"member"}})
	sessions := auth.NewSessionStore([]byte("guard-secret"), 30*time.Minute, clock)
	rbac := auth.NewRBAC(func(name string) []string {
		roles, _ := users.SnapshotRoles(name)
		return roles
	})
	rbac.GrantRole("member", "doc:read")
	th := auth.NewThrottler(auth.ThrottleConfig{MaxFailures: 2, Window: 10 * time.Minute, Lockout: 5 * time.Minute}, clock)
	svc := auth.NewService(users, sessions, rbac, th, clock)
	return fixture{
		svc:   svc,
		clock: clock,
		users: users,
		login: func(u, p string) string {
			tok, err := svc.Login(u, p)
			if err != nil {
				t.Fatalf("登录失败: %v", err)
			}
			return tok
		},
	}
}

// TestEntryDecisions 业务：不同入口（仅登录入口 / 权限入口）下三类请求的结论一致性。
func TestEntryDecisions(t *testing.T) {
	f := buildFixture(t)
	loginEntry := New(f.svc, "")          // 仅要求登录
	readEntry := New(f.svc, "doc:read")   // 要求读权限
	writeEntry := New(f.svc, "doc:write") // 要求写权限
	token := f.login("alice", "pw")

	t.Run("未登录：两个入口都给出 unauthenticated", func(t *testing.T) {
		for name, e := range map[string]*Entry{"登录入口": loginEntry, "权限入口": writeEntry} {
			d := e.Check("")
			if d.Allowed || d.Reason != auth.ReasonUnauthenticated {
				t.Fatalf("%s 空令牌应 unauthenticated，实际 %+v", name, d)
			}
		}
		t.Logf("业务[入口一致性] 用例[未登录] 通过：登录入口与权限入口均 unauthenticated")
	})

	t.Run("已登录：仅登录入口放行，写权限入口 forbidden", func(t *testing.T) {
		if d := loginEntry.Check(token); !d.Allowed {
			t.Fatalf("登录入口应放行，实际 %+v", d)
		}
		if d := readEntry.Check(token); !d.Allowed {
			t.Fatalf("有 doc:read 应放行，实际 %+v", d)
		}
		if d := writeEntry.Check(token); d.Allowed || d.Reason != auth.ReasonForbidden {
			t.Fatalf("无 doc:write 应 forbidden，实际 %+v", d)
		}
		t.Logf("业务[入口一致性] 用例[登录但无权限] 通过：登录入口放行、写入口 forbidden，结论可区分")
	})

	t.Run("篡改/失效凭证：权限入口也返回凭证类原因而非 forbidden", func(t *testing.T) {
		if d := writeEntry.Check(token + "xx"); d.Allowed || d.Reason != auth.ReasonMalformedToken {
			t.Fatalf("篡改令牌应为 malformed_token，实际 %+v", d)
		}
		if err := f.svc.Logout(token); err != nil {
			t.Fatalf("登出失败: %v", err)
		}
		if d := readEntry.Check(token); d.Allowed || d.Reason != auth.ReasonRevokedSession {
			t.Fatalf("失效令牌应为 revoked_session，实际 %+v", d)
		}
		t.Logf("业务[入口一致性] 用例[凭证失效优先于授权] 通过：篡改=malformed，登出后=revoked")
	})
}

// TestEntryLockout 业务：登录入口在节流锁定期间拒绝并可在窗口后恢复。
func TestEntryLockout(t *testing.T) {
	f := buildFixture(t)
	for i := 0; i < 2; i++ {
		if _, err := f.svc.Login("alice", "bad"); err.Reason != auth.ReasonInvalidCredential {
			t.Fatalf("失败结论异常: %v", err)
		}
	}
	_, err := f.svc.Login("alice", "pw")
	if err == nil || err.Reason != auth.ReasonTooManyAttempts {
		t.Fatalf("锁定期间应 too_many_attempts，实际 %v", err)
	}
	t.Logf("业务[入口节流] 用例[锁定期间拒绝] 通过：原因=too_many_attempts 锁定至=%s",
		err.LockedUntil.Format(time.RFC3339))

	f.clock.Advance(5 * time.Minute)
	token, err := f.svc.Login("alice", "pw")
	if err != nil {
		t.Fatalf("窗口结束后应恢复，实际 %v", err)
	}
	if d := New(f.svc, "").Check(token); !d.Allowed {
		t.Fatalf("恢复后应可访问，实际 %+v", d)
	}
	t.Logf("业务[入口节流] 用例[窗口后恢复] 通过：锁定解除，登录与访问恢复")
}

// TestMiddlewareStatus 业务：HTTP 中间件把结论映射为可解释的状态码与 JSON 正文。
func TestMiddlewareStatus(t *testing.T) {
	f := buildFixture(t)
	token := f.login("alice", "pw")
	cases := []struct {
		name       string
		entry      *Entry
		authHeader string
		wantStatus int
		wantReason auth.RejectReason
	}{
		{"未登录", New(f.svc, "doc:read"), "", http.StatusUnauthorized, auth.ReasonUnauthenticated},
		{"篡改令牌", New(f.svc, "doc:read"), "Bearer " + token + "xx", http.StatusUnauthorized, auth.ReasonMalformedToken},
		{"已登录无权限", New(f.svc, "doc:write"), "Bearer " + token, http.StatusForbidden, auth.ReasonForbidden},
		{"有权限", New(f.svc, "doc:read"), "Bearer " + token, http.StatusOK, auth.ReasonNone},
	}
	for _, c := range cases {
		h := c.entry.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if c.authHeader != "" {
			req.Header.Set("Authorization", c.authHeader)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.wantStatus {
			t.Fatalf("%s: 状态码期望 %d，实际 %d，正文=%s", c.name, c.wantStatus, rec.Code, rec.Body.String())
		}
		if c.wantReason != "" {
			var body struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s: 正文不是合法 JSON: %v", c.name, err)
			}
			if body.Reason != string(c.wantReason) {
				t.Fatalf("%s: reason 期望 %s，实际 %s", c.name, c.wantReason, body.Reason)
			}
		}
		t.Logf("业务[HTTP映射] 用例[%s] 通过：HTTP %d reason=%s", c.name, rec.Code, c.wantReason)
	}
}
