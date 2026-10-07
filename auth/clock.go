package auth

import "time"

// Clock 抽象时间来源，便于测试中确定性控制过期与窗口恢复。
type Clock interface {
	Now() time.Time
}

// realClock 使用系统真实时间。
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// NewRealClock 返回系统时钟。
func NewRealClock() Clock { return realClock{} }

// FakeClock 为测试提供可控时间。
type FakeClock struct {
	now time.Time
}

// NewFakeClock 以 t 为初始时间创建假时钟。
func NewFakeClock(t time.Time) *FakeClock { return &FakeClock{now: t} }

// Now 返回当前假时间。
func (c *FakeClock) Now() time.Time { return c.now }

// Advance 将假时间向前推进 d。
func (c *FakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }
