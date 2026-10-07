package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

const businessSession = "会话与令牌生命周期"

func TestSessionCreateValidate(t *testing.T) {
	m, _ := newTestManager(time.Hour, 30*time.Minute)
	token, err := m.Create("alice")
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	sess, err := m.Validate(token)
	if err != nil {
		t.Fatalf("校验新令牌失败: %v", err)
	}
	if sess.Username != "alice" {
		t.Fatalf("用户名不匹配: %s", sess.Username)
	}
	caseLog(t, businessSession, "创建后令牌立即可校验", "通过")
}

func TestSessionMissingToken(t *testing.T) {
	m, _ := newTestManager(time.Hour, time.Minute)
	if _, err := m.Validate(""); err == nil {
		t.Fatal("空令牌应当被拒绝")
	} else {
		reasonIs(t, err, ReasonNoCredentials)
	}
	caseLog(t, businessSession, "未携带凭证 => no_credentials", "通过")
}

func TestSessionMalformedAndTampered(t *testing.T) {
	m, _ := newTestManager(time.Hour, time.Minute)
	token, _ := m.Create("alice")

	// 格式非法：缺少分隔段。
	if _, err := m.Validate("not-a-valid-token"); err != nil {
		reasonIs(t, err, ReasonMalformedToken)
	}
	// 篡改签名：在 base64 字母表内翻转签名段末位字符。
	tampered := tamperSignature(token)
	if _, err := m.Validate(tampered); err != nil {
		reasonIs(t, err, ReasonBadSignature)
	}
	// 另一把密钥签发的令牌 => 签名不匹配。
	other := NewTokenCodec([]byte("another-secret")).Issue(TokenClaims{SessionID: "x"})
	if _, err := m.Validate(other); err != nil {
		reasonIs(t, err, ReasonBadSignature)
	}
	caseLog(t, businessSession, "格式错误/篡改签名/异密钥分别识别", "通过")
}

func TestSessionAbsoluteExpiry(t *testing.T) {
	m, clock := newTestManager(time.Hour, 10*time.Minute)
	token, _ := m.Create("alice")

	clock.Advance(61 * time.Minute) // 超过绝对寿命
	if _, err := m.Validate(token); err != nil {
		reasonIs(t, err, ReasonSessionExpired)
	}
	caseLog(t, businessSession, "绝对寿命到期 => session_expired", "通过")
}

func TestSessionIdleExpiry(t *testing.T) {
	m, clock := newTestManager(2*time.Hour, 30*time.Minute)
	token, _ := m.Create("alice")

	clock.Advance(20 * time.Minute) // 仍在空闲窗口内
	if _, err := m.Validate(token); err != nil {
		t.Fatalf("空闲窗口内校验不应失败: %v", err)
	}
	clock.Advance(31 * time.Minute) // 自上次活动后超过空闲窗口
	if _, err := m.Validate(token); err != nil {
		reasonIs(t, err, ReasonSessionExpired)
	}
	caseLog(t, businessSession, "空闲超时且无活动 => session_expired", "通过")
}

func TestSessionRevokeAndReuse(t *testing.T) {
	m, _ := newTestManager(time.Hour, time.Minute)
	token, _ := m.Create("alice")

	if err := m.Revoke(token); err != nil {
		t.Fatalf("首次失效失败: %v", err)
	}
	// 失效后重用原令牌必须被拒绝。
	if _, err := m.Validate(token); err != nil {
		reasonIs(t, err, ReasonSessionRevoked)
	}
	// 重复失效幂等成功。
	if err := m.Revoke(token); err != nil {
		t.Fatalf("重复失效应当幂等，实际: %v", err)
	}
	// 失效后续期也必须被拒绝。
	if _, _, err := m.Renew(token); err != nil {
		reasonIs(t, err, ReasonSessionRevoked)
	}
	caseLog(t, businessSession, "失效后原令牌不可用且重复失效幂等", "通过")
}

func TestSessionRenewBasicAndDuplicate(t *testing.T) {
	m, _ := newTestManager(time.Hour, 30*time.Minute)
	token, _ := m.Create("alice")

	newToken, _, err := m.Renew(token)
	if err != nil {
		t.Fatalf("首次续期应成功: %v", err)
	}
	// 旧令牌同一代再次续期 => 重复续期。
	if _, _, err := m.Renew(token); err != nil {
		reasonIs(t, err, ReasonDuplicateRenewal)
	}
	// 新令牌有效，旧令牌仍可用于普通校验（同一会话，新代）。
	if _, err := m.Validate(newToken); err != nil {
		t.Fatalf("续期后新令牌应有效: %v", err)
	}
	// 新代令牌可以再续期一次。
	if _, _, err := m.Renew(newToken); err != nil {
		t.Fatalf("新代令牌续期应成功: %v", err)
	}
	caseLog(t, businessSession, "顺序续期：旧代重复拒绝、新代可续", "通过")
}

// TestSessionConcurrentRenew 是关键并发场景：同一会话的同一代令牌
// 被大量 goroutine 同时续期，必须恰好一次成功，其余全部重复续期。
func TestSessionConcurrentRenew(t *testing.T) {
	m, _ := newTestManager(time.Hour, 30*time.Minute)
	token, _ := m.Create("alice")

	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, duplicate, other := 0, 0, 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _, err := m.Renew(token)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			default:
				if ae, ok := err.(*AuthError); ok && ae.Reason == ReasonDuplicateRenewal {
					duplicate++
				} else {
					other++
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("[业务=%s] 用例=%d 并发续期 => 成功=%d 重复拒绝=%d 其他=%d",
		businessSession, n, success, duplicate, other)
	if success != 1 {
		t.Fatalf("并发续期成功次数应为 1，实际 %d", success)
	}
	if duplicate != n-1 {
		t.Fatalf("重复续期拒绝次数应为 %d，实际 %d", n-1, duplicate)
	}
	if other != 0 {
		t.Fatalf("不应出现其他结论，实际 %d", other)
	}
	caseLog(t, businessSession, fmt.Sprintf("%d 并发同代续期恰好一次成功", n), "通过")
}

// TestSessionRevokeRaceWithValidate 验证失效与校验竞争下，
// 一旦失效发生，之后的任何重用都不会成功。
func TestSessionRevokeRaceWithValidate(t *testing.T) {
	m, _ := newTestManager(time.Hour, time.Minute)
	token, _ := m.Create("alice")

	var wg sync.WaitGroup
	var rejectedAfterRevoke atomicBool
	revoked := make(chan struct{})

	wg.Add(2)
	go func() { // 失效方
		defer wg.Done()
		_ = m.Revoke(token)
		close(revoked)
	}()
	go func() { // 重用方
		defer wg.Done()
		<-revoked
		if _, err := m.Validate(token); err != nil {
			if ae, ok := err.(*AuthError); ok && ae.Reason == ReasonSessionRevoked {
				rejectedAfterRevoke.set()
			}
		}
	}()
	wg.Wait()

	if !rejectedAfterRevoke.get() {
		t.Fatal("失效完成后重用必须被拒绝")
	}
	caseLog(t, businessSession, "失效完成后并发重用必被拒绝", "通过")
}
