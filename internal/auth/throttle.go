package auth

import (
	"sync"
	"time"
)

// ThrottleConfig 描述失败锁定策略。
type ThrottleConfig struct {
	MaxFailures int           // 连续失败达到此次数后进入锁定
	Window      time.Duration // 失败计数窗口；窗口外的旧失败自动失效
	Lockout     time.Duration // 锁定持续时长，结束后自动恢复
}

// DefaultThrottleConfig 给出默认策略：5 次失败锁定 5 分钟，计数窗口 10 分钟。
func DefaultThrottleConfig() ThrottleConfig {
	return ThrottleConfig{
		MaxFailures: 5,
		Window:      10 * time.Minute,
		Lockout:     5 * time.Minute,
	}
}

// attempt 记录某身份最近一次失败时间，以及锁定截止时间。
type attempt struct {
	count       int
	lastFailAt  time.Time
	lockedUntil time.Time
}

// Throttler 按身份维度维护登录失败计数与锁定状态。
// 所有状态在单把互斥锁下更新，保证并发下计数与锁定准确。
type Throttler struct {
	mu    sync.Mutex
	store map[string]*attempt
	cfg   ThrottleConfig
	clock Clock
}

// NewThrottler 创建限流器。
func NewThrottler(cfg ThrottleConfig, clock Clock) *Throttler {
	if clock == nil {
		clock = RealClock{}
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	return &Throttler{
		store: make(map[string]*attempt),
		cfg:   cfg,
		clock: clock,
	}
}

// normalize 在持锁状态下清理过期状态：
// 锁定到期 -> 清空计数；计数窗口外的失败 -> 计数作废。
func (a *attempt) normalize(now time.Time, cfg ThrottleConfig) {
	if !a.lockedUntil.IsZero() && !now.Before(a.lockedUntil) {
		a.count = 0
		a.lockedUntil = time.Time{}
		a.lastFailAt = time.Time{}
		return
	}
	if a.count > 0 && now.Sub(a.lastFailAt) > cfg.Window {
		a.count = 0
		a.lastFailAt = time.Time{}
	}
}

// Check 在登录前判断身份是否处于锁定中；窗口结束后自动放行。
func (t *Throttler) Check(identity string) *RejectError {
	now := t.clock.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.store[identity]
	if a == nil {
		return nil
	}
	a.normalize(now, t.cfg)
	if !a.lockedUntil.IsZero() && now.Before(a.lockedUntil) {
		return &RejectError{
			Reason:      ReasonTooManyAttempts,
			Message:     "too many failed attempts, try later",
			LockedUntil: a.lockedUntil,
		}
	}
	return nil
}

// RecordFailure 记录一次失败；达到阈值即进入锁定。
// 即便在锁定期间继续发生失败尝试，也不延长锁定期，避免无限锁定。
func (t *Throttler) RecordFailure(identity string) {
	now := t.clock.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.store[identity]
	if a == nil {
		a = &attempt{}
		t.store[identity] = a
	}
	a.normalize(now, t.cfg)
	if !a.lockedUntil.IsZero() && now.Before(a.lockedUntil) {
		return
	}
	a.count++
	a.lastFailAt = now
	if a.count >= t.cfg.MaxFailures {
		a.lockedUntil = now.Add(t.cfg.Lockout)
	}
}

// RecordSuccess 登录成功后清空该身份的计数与锁定状态。
func (t *Throttler) RecordSuccess(identity string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.store, identity)
}

// State 返回该身份当前的失败次数与锁定截止时间（用于观测/测试）。
func (t *Throttler) State(identity string) (failures int, lockedUntil time.Time) {
	now := t.clock.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.store[identity]
	if a == nil {
		return 0, time.Time{}
	}
	a.normalize(now, t.cfg)
	return a.count, a.lockedUntil
}
