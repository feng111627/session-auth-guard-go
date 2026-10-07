package auth

import (
	"sync"
	"time"
)

// ThrottleConfig 定义失败阈值与窗口/锁定时长。
type ThrottleConfig struct {
	// MaxFailures 在一个计数窗口内达到该失败次数后进入拒绝状态。
	MaxFailures int
	// Window 计数窗口：从首次失败起计时，窗口结束后计数清零、自动恢复。
	Window time.Duration
	// LockDuration 阈值触发后的硬锁定时长（应不大于 Window）。
	// 硬锁定期内结论为 locked；硬锁定结束但窗口未结束期间结论为 throttled。
	LockDuration time.Duration
}

// identityState 是单个身份维度的计数与锁定状态。
type identityState struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// Throttler 按身份维度记录登录失败计数与锁定状态。
// 身份通常是用户名；不存在的用户名同样被计数，从而对
// “账号是否存在”保持一致的对外结论。
type Throttler struct {
	mu     sync.Mutex
	states map[string]*identityState
	// identityLocks 为每个身份提供一把串行锁，使同一身份的
	// “检查 -> 凭据验证 -> 登记”整体互斥，杜绝 Check/Record 间的 TOCTOU；
	// 不同身份各持各锁，仍然完全并行。
	lockMu        sync.Mutex
	identityLocks map[string]*sync.Mutex
	clock         Clock
	config        ThrottleConfig
}

// NewThrottler 创建节流器。
func NewThrottler(clock Clock, config ThrottleConfig) *Throttler {
	return &Throttler{
		states:        map[string]*identityState{},
		identityLocks: map[string]*sync.Mutex{},
		clock:         clock,
		config:        config,
	}
}

// LockIdentity 锁住指定身份的登录尝试临界区，返回解锁函数。
// 同一身份的尝试因此串行，保证失败计数在并发下精确。
func (t *Throttler) LockIdentity(identity string) func() {
	t.lockMu.Lock()
	l, ok := t.identityLocks[identity]
	if !ok {
		l = &sync.Mutex{}
		t.identityLocks[identity] = l
	}
	t.lockMu.Unlock()
	l.Lock()
	return l.Unlock
}

// normalize 必须在持有 t.mu 时调用：按当前时间推进/复位状态，
// 实现窗口结束与锁定结束后的自动恢复。
func (t *Throttler) normalize(st *identityState, now time.Time) {
	if st.windowStart.IsZero() {
		return
	}
	// 固定计数窗口结束：计数与锁定全部清零，自动恢复可登录。
	if !now.Before(st.windowStart.Add(t.config.Window)) {
		*st = identityState{}
	}
}

// Check 在登录密码校验前调用：返回当前是否允许尝试，
// 以及拒绝原因（硬锁定 locked / 窗口节流 throttled）。
func (t *Throttler) Check(identity string, now time.Time) (bool, Reason) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.states[identity]
	if st == nil {
		return true, ""
	}
	t.normalize(st, now)
	if st.failures < t.config.MaxFailures {
		return true, ""
	}
	// 已达到阈值：硬锁定期内 locked，其余窗口时间 throttled。
	if now.Before(st.lockedUntil) {
		return false, ReasonLocked
	}
	return false, ReasonThrottled
}

// RecordFailure 记录一次失败并在达到阈值时进入硬锁定。
// 自增在互斥内完成，并发失败计数精确无丢失。
func (t *Throttler) RecordFailure(identity string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.states[identity]
	if st == nil {
		st = &identityState{}
		t.states[identity] = st
	}
	t.normalize(st, now)
	if st.failures == 0 {
		// 新窗口从本窗口第一次失败开始计时。
		st.windowStart = now
	}
	st.failures++
	if st.failures == t.config.MaxFailures {
		st.lockedUntil = now.Add(t.config.LockDuration)
	}
}

// RecordSuccess 登录成功后清零该身份的计数与锁定。
func (t *Throttler) RecordSuccess(identity string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, identity)
}

// Reset 清空某身份全部状态（测试辅助）。
func (t *Throttler) Reset(identity string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, identity)
}

// State 返回某身份当前的失败次数与锁定截止时间快照（自动恢复已应用）。
func (t *Throttler) State(identity string, now time.Time) (failures int, lockedUntil time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.states[identity]
	if st == nil {
		return 0, time.Time{}
	}
	t.normalize(st, now)
	return st.failures, st.lockedUntil
}
