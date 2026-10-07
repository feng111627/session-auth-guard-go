package auth

import (
	"testing"
	"time"
)

func newServiceFixture() (*FixedClock, *Service, *UserStore) {
	clock := &FixedClock{T: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	users := NewUserStore()
	users.AddUser(&User{ID: "u1", Username: "alice", PasswordHash: HashPassword("correct-horse"), Roles: []string{"member"}})
	users.AddUser(&User{ID: "u2", Username: "bob", PasswordHash: HashPassword("hunter2"), Roles: []string{"viewer"}})
	sessions := NewSessionStore([]byte("fixture-secret"), 30*time.Minute, clock)
	rbac := NewRBAC(func(name string) []string {
		roles, _ := users.SnapshotRoles(name)
		return roles
	})
	rbac.GrantRole("member", "doc:read")
	rbac.GrantRole("admin", "doc:read", "doc:write")
	th := NewThrottler(ThrottleConfig{MaxFailures: 3, Window: 10 * time.Minute, Lockout: 5 * time.Minute}, clock)
	svc := NewService(users, sessions, rbac, th, clock)
	return clock, svc, users
}

// TestServiceLogin 业务：登录签发与统一的失败结论。
func TestServiceLogin(t *testing.T) {
	_, svc, _ := newServiceFixture()

	t.Run("正确账密签发可用令牌", func(t *testing.T) {
		token, err := svc.Login("alice", "correct-horse")
		if err != nil || token == "" {
			t.Fatalf("登录应成功，实际 token=%q err=%v", token, err)
		}
		sess, err := svc.Authenticate(token)
		if err != nil {
			t.Fatalf("签发的令牌应可通过认证，实际 %v", err)
		}
		t.Logf("业务[登录] 用例[成功签发] 通过：用户=%s 会话到期=%s", sess.Username, sess.ExpiresAt.Format(time.RFC3339))
	})

	t.Run("账号不存在与密码错误对外结论完全一致", func(t *testing.T) {
		_, err1 := svc.Login("ghost", "whatever")
		_, err2 := svc.Login("alice", "wrong-password")
		if err1 == nil || err2 == nil {
			t.Fatal("两种情况都应失败")
		}
		if err1.Reason != ReasonInvalidCredential || err2.Reason != ReasonInvalidCredential {
			t.Fatalf("原因都应为 invalid_credential，实际 %s / %s", err1.Reason, err2.Reason)
		}
		if err1.Error() != err2.Error() {
			t.Fatalf("对外消息必须一致以防枚举账号，实际 %q / %q", err1.Error(), err2.Error())
		}
		t.Logf("业务[登录] 用例[账号枚举防护] 通过：不存在账号与错误密码均返回 %q", err1.Error())
	})
}

// TestServiceAuthzDistinction 业务：未认证 vs 已认证无权限，结论可区分。
func TestServiceAuthzDistinction(t *testing.T) {
	_, svc, _ := newServiceFixture()
	token, _ := svc.Login("alice", "correct-horse")

	t.Run("无令牌由入口层归为 unauthenticated，服务端解析伪造令牌为 malformed", func(t *testing.T) {
		if _, err := svc.Authenticate("garbage"); err == nil || err.Reason != ReasonMalformedToken {
			t.Fatalf("伪造令牌应为 malformed_token，实际 %v", err)
		}
		t.Logf("业务[认证/授权区分] 用例[伪造凭证] 通过：malformed_token")
	})

	t.Run("已登录但缺少权限为 forbidden", func(t *testing.T) {
		if _, err := svc.Authorize(token, "doc:write"); err == nil || err.Reason != ReasonForbidden {
			t.Fatalf("应返回 forbidden，实际 %v", err)
		}
		t.Logf("业务[认证/授权区分] 用例[登录但无权] 通过：forbidden，与凭证类错误可区分")
	})

	t.Run("持有权限则通过", func(t *testing.T) {
		sess, err := svc.Authorize(token, "doc:read")
		if err != nil {
			t.Fatalf("应授权通过，实际 %v", err)
		}
		t.Logf("业务[认证/授权区分] 用例[有权放行] 通过：用户=%s", sess.Username)
	})
}

// TestServicePermissionChangeLive 业务：权限/角色调整对既有会话即时生效，
// 且旧令牌在整个过程中持续可用。
func TestServicePermissionChangeLive(t *testing.T) {
	_, svc, users := newServiceFixture()
	token, _ := svc.Login("alice", "correct-horse")

	// 1) 提权：旧令牌立刻获得新权限
	users.SetRoles("alice", []string{"admin"})
	if _, err := svc.Authorize(token, "doc:write"); err != nil {
		t.Fatalf("提权后旧令牌应可写文档，实际 %v", err)
	}
	t.Logf("业务[权限即时生效] 用例[提权即时生效] 通过：同一令牌在角色调整后可 doc:write")

	// 2) 降权：旧令牌立刻失去权限，但令牌本身仍然有效
	users.SetRoles("alice", []string{"member"})
	if _, err := svc.Authorize(token, "doc:write"); err == nil || err.Reason != ReasonForbidden {
		t.Fatalf("降权后应 forbidden，实际 %v", err)
	}
	if _, err := svc.Authenticate(token); err != nil {
		t.Fatalf("降权不应使旧令牌失效，实际 %v", err)
	}
	t.Logf("业务[权限即时生效] 用例[降权不失效凭证] 通过：doc:write 被拒，但令牌认证仍通过")

}

// TestServiceLoginLockoutFlow 业务：连续失败锁定，锁定期间正确密码也被拒，到期恢复。
func TestServiceLoginLockoutFlow(t *testing.T) {
	clock, svc, _ := newServiceFixture()

	// 同一身份连续 3 次密码错误；另外验证“不存在账号”对外结论一致
	// （幽灵账号的计数记在其自身名下，不影响 alice 的锁定判定）。
	if _, err := svc.Login("ghost", "x"); err.Reason != ReasonInvalidCredential {
		t.Fatalf("不存在账号结论异常: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.Login("alice", "bad"); err.Reason != ReasonInvalidCredential {
			t.Fatalf("第 %d 次失败结论异常: %v", i+1, err)
		}
	}

	if _, err := svc.Login("alice", "correct-horse"); err == nil || err.Reason != ReasonTooManyAttempts {
		t.Fatalf("锁定后即使密码正确也应拒绝(too_many_attempts)，实际 %v", err)
	}
	t.Logf("业务[登录锁定流程] 用例[达阈值拒绝正确密码] 通过：3 次失败后返回 too_many_attempts")

	clock.Advance(5 * time.Minute) // 锁定期满
	token, err := svc.Login("alice", "correct-horse")
	if err != nil || token == "" {
		t.Fatalf("窗口结束后应自动恢复登录，实际 %v", err)
	}
	if _, err := svc.Authenticate(token); err != nil {
		t.Fatalf("恢复后签发的令牌应可用，实际 %v", err)
	}
	t.Logf("业务[登录锁定流程] 用例[窗口结束恢复] 通过：锁定解除并成功登录")
}

// TestServiceRenewAndLogout 业务：通过服务门面续期与登出。
func TestServiceRenewAndLogout(t *testing.T) {
	clock, svc, _ := newServiceFixture()
	token, _ := svc.Login("bob", "hunter2")
	originalExpiry := clock.Now().Add(30 * time.Minute)

	clock.Advance(20 * time.Minute)
	newToken, err := svc.Renew(token)
	if err != nil {
		t.Fatalf("续期失败: %v", err)
	}
	if newToken != token {
		t.Fatal("续期后令牌值应保持不变")
	}
	sess, _ := svc.Authenticate(token)
	want := clock.Now().Add(30 * time.Minute)
	if !sess.ExpiresAt.Equal(want) || sess.Version != 1 {
		t.Fatalf("续期结果异常 expiry=%s version=%d", sess.ExpiresAt, sess.Version)
	}
	t.Logf("业务[续期登出] 用例[续期延长有效期] 通过：%s -> %s",
		originalExpiry.Format("15:04"), sess.ExpiresAt.Format("15:04"))

	if err := svc.Logout(token); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	if _, err := svc.Authenticate(token); err == nil || err.Reason != ReasonRevokedSession {
		t.Fatalf("登出后令牌应 revoked，实际 %v", err)
	}
	t.Logf("业务[续期登出] 用例[登出后重用拒绝] 通过：revoked_session")
}
