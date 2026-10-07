package auth

import (
	"sync"
	"testing"
	"time"
)

const businessThrottle = "登录节流与锁定"

func newThrottleService(t *testing.T) (*Service, *FakeClock) {
	t.Helper()
	clock := NewFakeClock(fixedNow())
	svc := NewServiceWithClock(ServiceConfig{
		TokenSecret: []byte("throttle-secret"),
		Sessions:    ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute},
		Throttle: ThrottleConfig{
			MaxFailures:  3,
			Window:       60 * time.Second,
			LockDuration: 30 * time.Second,
		},
	}, clock)
	svc.Users().AddUser(User{Username: "carol", PasswordHash: HashPassword("correct"), Roles: nil})
	return svc, clock
}

func TestLoginUnknownUserAndWrongPasswordSameReason(t *testing.T) {
	svc, _ := newThrottleService(t)

	// 不存在的账号与错误口令返回完全一致的对外结论。
	_, _, errUnknown := svc.Login("ghost", "whatever")
	reasonIs(t, errUnknown, ReasonInvalidCredentials)
	_, _, errWrong := svc.Login("carol", "wrong")
	reasonIs(t, errWrong, ReasonInvalidCredentials)
	if errUnknown.Error() == "" || errWrong.Error() == "" {
		t.Fatal("错误信息不应为空")
	}
	caseLog(t, businessThrottle, "不存在账号与密码错误对外统一 invalid_credentials", "通过")

	// 两者都按身份计数；不存在账号也被独立计数。
	fGhost, _ := svc.Throttler().State("ghost", svc.clock.Now())
	fCarol, _ := svc.Throttler().State("carol", svc.clock.Now())
	if fGhost != 1 || fCarol != 1 {
		t.Fatalf("计数应为 ghost=1 carol=1，实际 ghost=%d carol=%d", fGhost, fCarol)
	}
	caseLog(t, businessThrottle, "两类失败均按身份维度计数", "通过")
}

func TestLoginLockThenAutoRecover(t *testing.T) {
	svc, clock := newThrottleService(t)

	// 前 2 次仍是普通凭据错误。
	for i := 1; i <= 2; i++ {
		if _, _, err := svc.Login("carol", "bad"); err == nil {
			t.Fatalf("第 %d 次错误登录应失败", i)
		}
	}
	// 第 3 次达到阈值：本次仍是凭据错误，之后进入硬锁定。
	_, _, err := svc.Login("carol", "bad")
	reasonIs(t, err, ReasonInvalidCredentials)

	// 硬锁定期内：即使口令正确也被 locked 拒绝。
	_, _, err = svc.Login("carol", "correct")
	reasonIs(t, err, ReasonLocked)
	caseLog(t, businessThrottle, "达到阈值后硬锁定(正确口令也拒绝) => locked(429)", "通过")

	// 硬锁定结束、窗口未结束：throttled。
	clock.Advance(31 * time.Second)
	_, _, err = svc.Login("carol", "correct")
	reasonIs(t, err, ReasonThrottled)
	caseLog(t, businessThrottle, "硬锁定后窗口内 => throttled(429)", "通过")

	// 窗口结束：计数清零、自动恢复，正确口令可登录。
	clock.Advance(30 * time.Second)
	token, _, err := svc.Login("carol", "correct")
	if err != nil {
		t.Fatalf("窗口结束后应自动恢复并登录成功，实际: %v", err)
	}
	if token == "" {
		t.Fatal("恢复后应签发令牌")
	}
	caseLog(t, businessThrottle, "窗口结束自动恢复并可正常登录", "通过")

	// 成功登录后计数清零：此前失败不再影响后续。
	failures, _ := svc.Throttler().State("carol", svc.clock.Now())
	if failures != 0 {
		t.Fatalf("成功登录后失败计数应为 0，实际 %d", failures)
	}
	caseLog(t, businessThrottle, "成功登录清零计数", "通过")
}

func TestThrottleCheckStateTransitions(t *testing.T) {
	clock := NewFakeClock(fixedNow())
	th := NewThrottler(clock, ThrottleConfig{MaxFailures: 2, Window: time.Minute, LockDuration: 20 * time.Second})
	now := clock.Now()

	th.RecordFailure("u", now)
	if ok, _ := th.Check("u", now); !ok {
		t.Fatal("未达阈值应允许尝试")
	}
	th.RecordFailure("u", now)
	if ok, r := th.Check("u", now); ok || r != ReasonLocked {
		t.Fatalf("达阈值应 locked，实际 ok=%v reason=%s", ok, r)
	}
	clock.Advance(21 * time.Second)
	if ok, r := th.Check("u", clock.Now()); ok || r != ReasonThrottled {
		t.Fatalf("硬锁结束窗口内应 throttled，实际 ok=%v reason=%s", ok, r)
	}
	clock.Advance(40 * time.Second)
	if ok, _ := th.Check("u", clock.Now()); !ok {
		t.Fatal("窗口结束应自动恢复")
	}
	caseLog(t, businessThrottle, "计数->锁定->节流->恢复 状态迁移正确", "通过")
}

// TestThrottleConcurrentFailures 是关键并发场景：大量并发失败必须精确计数，
// 达到阈值后全部拒绝，不多不少。
func TestThrottleConcurrentFailures(t *testing.T) {
	clock := NewFakeClock(fixedNow())
	users := NewUserStore()
	users.AddUser(User{Username: "dave", PasswordHash: HashPassword("pw")})
	svc := &Service{
		users:      users,
		sessions:   NewSessionManager(NewSessionStore(), NewTokenCodec([]byte("x")), clock, ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour}),
		authorizer: NewAuthorizer(users),
		throttler:  NewThrottler(clock, ThrottleConfig{MaxFailures: 5, Window: time.Minute, LockDuration: 30 * time.Second}),
		clock:      clock,
	}

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	invalid, locked, other := 0, 0, 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _, err := svc.Login("dave", "bad")
			ae, _ := err.(*AuthError)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case ae != nil && ae.Reason == ReasonInvalidCredentials:
				invalid++
			case ae != nil && ae.Reason == ReasonLocked:
				locked++
			default:
				other++
			}
		}()
	}
	wg.Wait()

	t.Logf("[业务=%s] 用例=%d 并发失败 => 凭据错误=%d 锁定=%d 其他=%d",
		businessThrottle, n, invalid, locked, other)
	if other != 0 {
		t.Fatalf("不应出现其他结论，实际 %d", other)
	}
	if invalid != 5 {
		t.Fatalf("恰好前 5 次（阈值）为凭据错误，实际 %d", invalid)
	}
	if locked != 15 {
		t.Fatalf("其余 15 次应被锁定拒绝，实际 %d", locked)
	}
	failures, _ := svc.Throttler().State("dave", clock.Now())
	if failures != 5 {
		t.Fatalf("并发后失败计数应精确为 5，实际 %d", failures)
	}
	caseLog(t, businessThrottle, "20 并发失败精确计数到阈值并锁定", "通过")
}

func TestThrottleUnknownIdentitySeparatelyLocked(t *testing.T) {
	svc, _ := newThrottleService(t)
	// 对不存在账号打到阈值，也会锁定该“身份”，且不影响真实账号。
	for i := 0; i < 3; i++ {
		svc.Login("ghost", "x")
	}
	if _, _, err := svc.Login("ghost", "x"); err == nil {
		t.Fatal("不存在账号达阈值后也应被拒绝")
	} else {
		reasonIs(t, err, ReasonLocked)
	}
	// 真实账号 carol 未受影响，仍可正常登录。
	if token, _, err := svc.Login("carol", "correct"); err != nil || token == "" {
		t.Fatalf("不存在账号的锁定不应牵连真实账号: %v", err)
	}
	caseLog(t, businessThrottle, "不存在账号独立锁定且不牵连真实账号", "通过")
}
