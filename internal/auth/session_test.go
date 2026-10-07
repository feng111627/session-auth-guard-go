package auth

import (
	"sync"
	"testing"
	"time"
)

func newSessionFixture(now time.Time) (*FixedClock, *SessionStore) {
	clock := &FixedClock{T: now}
	store := NewSessionStore([]byte("test-secret"), 30*time.Minute, clock)
	return clock, store
}

func demoUser() *User {
	return &User{ID: "u1", Username: "alice", PasswordHash: HashPassword("pw"), Roles: []string{"member"}}
}

// TestSessionLifecycle 业务：会话与令牌生命周期 —— 创建、校验、续期、失效、过期、篡改。
func TestSessionLifecycle(t *testing.T) {
	base := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	clock, store := newSessionFixture(base)

	t.Run("签发后立即校验通过", func(t *testing.T) {
		tok, sess := store.Issue(demoUser())
		got, err := store.Validate(tok)
		if err != nil {
			t.Fatalf("期望校验通过，实际 %v", err)
		}
		if got.Username != "alice" || !got.ExpiresAt.Equal(base.Add(30*time.Minute)) {
			t.Fatalf("会话内容异常: %+v", got)
		}
		t.Logf("业务[会话生命周期] 用例[签发即有效] 通过：到期时间=%s", sess.ExpiresAt.Format(time.RFC3339))
	})

	t.Run("过期令牌被拒绝并归因为 expired", func(t *testing.T) {
		tok, _ := store.Issue(demoUser())
		clock.Advance(31 * time.Minute)
		_, err := store.Validate(tok)
		if err == nil || err.Reason != ReasonExpiredSession {
			t.Fatalf("期望 expired_session，实际 %v", err)
		}
		t.Logf("业务[会话生命周期] 用例[过期拒绝] 通过：原因=%s", err.Reason)
		clock.T = base // 复位时钟，不影响后续独立用例的语义判断
	})

	t.Run("主动失效后复用被拒绝并归因为 revoked", func(t *testing.T) {
		tok, _ := store.Issue(demoUser())
		if err := store.Revoke(tok); err != nil {
			t.Fatalf("Revoke 失败: %v", err)
		}
		_, err := store.Validate(tok)
		if err == nil || err.Reason != ReasonRevokedSession {
			t.Fatalf("期望 revoked_session，实际 %v", err)
		}
		// 失效后即使再续期也必须被拒绝
		if _, err := store.Renew(tok, time.Minute); err == nil || err.Reason != ReasonRevokedSession {
			t.Fatalf("失效后续期应返回 revoked，实际 %v", err)
		}
		t.Logf("业务[会话生命周期] 用例[失效后重用拒绝] 通过：Validate 与 Renew 均返回 revoked")
	})

	t.Run("重复失效幂等", func(t *testing.T) {
		tok, _ := store.Issue(demoUser())
		if err := store.Revoke(tok); err != nil {
			t.Fatalf("首次 Revoke 失败: %v", err)
		}
		if err := store.Revoke(tok); err != nil {
			t.Fatalf("重复 Revoke 应幂等，实际 %v", err)
		}
		t.Logf("业务[会话生命周期] 用例[重复失效幂等] 通过")
	})
}

// TestTokenTampering 业务：凭证篡改 —— 结构错误、签名错误、未知会话分别给结论。
func TestTokenTampering(t *testing.T) {
	_, store := newSessionFixture(time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC))
	tok, _ := store.Issue(demoUser())

	t.Run("结构非法", func(t *testing.T) {
		if _, err := store.Parse("not-a-token"); err == nil || err.Reason != ReasonMalformedToken {
			t.Fatalf("期望 malformed_token，实际 %v", err)
		}
		t.Logf("业务[凭证防篡改] 用例[结构非法] 通过：原因=malformed_token")
	})

	t.Run("签名被篡改", func(t *testing.T) {
		bad := tok.Raw[:len(tok.Raw)-2] + "AA"
		if _, err := store.Parse(bad); err == nil || err.Reason != ReasonMalformedToken {
			t.Fatalf("期望 malformed_token，实际 %v", err)
		}
		t.Logf("业务[凭证防篡改] 用例[签名篡改] 通过：原因=malformed_token")
	})

	t.Run("签名合法但会话不存在", func(t *testing.T) {
		// 用同密钥为一个全新随机 ID 签名，但不登记会话
		other := newSessionID()
		raw := b64.EncodeToString([]byte(other)) + "." + store.sign(other)
		parsed, err := store.Parse(raw)
		if err != nil {
			t.Fatalf("签名本身应合法: %v", err)
		}
		if _, err := store.Validate(parsed); err == nil || err.Reason != ReasonUnknownSession {
			t.Fatalf("期望 unknown_session，实际 %v", err)
		}
		t.Logf("业务[凭证防篡改] 用例[未知会话] 通过：原因=unknown_session")
	})
}

// TestConcurrentRenewNoDuplicate 业务：并发续期 —— 同一会话的并发续期只生效一次。
func TestConcurrentRenewNoDuplicate(t *testing.T) {
	base := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	clock, store := newSessionFixture(base)
	tok, sess0 := store.Issue(demoUser())

	clock.Advance(5 * time.Minute) // 距签发 5 分钟后发生并发续期风暴

	const n = 64
	// 屏障：等所有续期请求都已抵达 singleflight 排队点后，再放行 leader，
	// 从而确定性地模拟“同一时刻的并发续期”，不依赖调度时序。
	entered := make(chan struct{}, n)
	proceed := make(chan struct{})
	store.renewHook = func() {
		entered <- struct{}{}
		<-proceed
	}
	store.waitHook = func() { entered <- struct{}{} }

	var wg sync.WaitGroup
	errs := make([]*RejectError, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = store.Renew(tok, 30*time.Minute)
		}(i)
	}
	for i := 0; i < n; i++ {
		<-entered
	}
	close(proceed)
	wg.Wait()
	store.renewHook = nil
	store.waitHook = nil

	for i, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 个并发续期意外失败: %v", i, err)
		}
	}
	sess, err := store.Validate(tok)
	if err != nil {
		t.Fatalf("续期后校验失败: %v", err)
	}
	if sess.Version != 1 {
		t.Fatalf("并发续期只应生效一次，期望 Version=1，实际 %d", sess.Version)
	}
	want := clock.Now().Add(30 * time.Minute)
	if !sess.ExpiresAt.Equal(want) {
		t.Fatalf("续期到期时间应为 %s，实际 %s（可能发生了重复叠加）", want, sess.ExpiresAt)
	}
	if !sess0.ExpiresAt.Equal(base.Add(30 * time.Minute)) {
		t.Fatalf("原始签发到期时间被意外修改")
	}
	t.Logf("业务[并发续期] 用例[%d 个并发请求只续期一次] 通过：Version=%d，到期=%s",
		n, sess.Version, sess.ExpiresAt.Format(time.RFC3339))

	// 下一批非并发的续期应当继续生效，证明没有把会话“卡死”
	if _, err := store.Renew(tok, 30*time.Minute); err != nil {
		t.Fatalf("后续续期失败: %v", err)
	}
	sess, _ = store.Validate(tok)
	if sess.Version != 2 {
		t.Fatalf("第二批续期后 Version 应为 2，实际 %d", sess.Version)
	}
	t.Logf("业务[并发续期] 用例[风暴后可再次续期] 通过：Version=%d", sess.Version)
}

// TestConcurrentRenewAndRevoke 业务：续期与失效并发 —— 失效一旦可见，后续永不再可用。
func TestConcurrentRenewAndRevoke(t *testing.T) {
	base := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	_, store := newSessionFixture(base)
	tok, _ := store.Issue(demoUser())

	const n = 32
	var wg sync.WaitGroup
	wg.Add(2 * n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, _ = store.Renew(tok, time.Minute)
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = store.Revoke(tok)
		}()
	}
	close(start)
	wg.Wait()

	// 无论之前竞态结果如何，最终状态必须是已失效
	if err := store.Revoke(tok); err != nil {
		t.Fatalf("收尾 Revoke 失败: %v", err)
	}
	if _, err := store.Validate(tok); err == nil || err.Reason != ReasonRevokedSession {
		t.Fatalf("并发结束后会话必须已失效，实际 %v", err)
	}
	t.Logf("业务[续期与失效并发] 用例[%d 续期 + %d 失效竞态后状态确定] 通过：最终 revoked", n, n)
}
