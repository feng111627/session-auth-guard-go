package auth

import "time"

// Clock 抽象当前时间，便于在测试中驱动过期与窗口恢复逻辑。
type Clock interface {
	Now() time.Time
}

// RealClock 使用系统墙上时间。
type RealClock struct{}

// Now 返回当前系统时间。
func (RealClock) Now() time.Time { return time.Now() }

// FixedClock 在测试中返回固定时间。
type FixedClock struct {
	T time.Time
}

// Now 返回固定时间点。
func (c FixedClock) Now() time.Time { return c.T }

// Advance 在测试中把固定时钟向前推进 d。
func (c *FixedClock) Advance(d time.Duration) { c.T = c.T.Add(d) }
