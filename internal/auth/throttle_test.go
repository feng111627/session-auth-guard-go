package auth

import (
	"sync"
	"testing"
	"time"
)

// TestThrottleLockAndRecover 业务：登录失败计数、锁定与窗口结束自动恢复。
func TestThrottleLockAndRecover(t *testing.T) {
	base := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	clock := &FixedClock{T: base}
	cfg := ThrottleConfig{MaxFailures: 3, Window: 10 * time.Minute, Lockout: 5 * time.Minute}
	th := NewThrottler(cfg, clock)

	t.Run("未达阈值不锁定", func(t *testing.T) {
		th.RecordFailure("alice")
		th.RecordFailure("alice")
		if err := th.Check("alice"); err != nil {
			t.Fatalf("2 次失败不应锁定，实际 %v", err)
		}
		failures, until := th.State("alice")
		if failures != 2 || !until.IsZero() {
			t.Fatalf("状态异常 failures=%d until=%v", failures, until)
		}
		t.Logf("业务[节流锁定] 用例[阈值内放行] 通过：失败 2/3，未锁定")
	})

	t.Run("达到阈值锁定并携带截止时间", func(t *testing.T) {
		th.RecordFailure("alice") // 第 3 次
		err := th.Check("alice")
		if err == nil || err.Reason != ReasonTooManyAttempts {
			t.Fatalf("应被锁定，实际 %v", err)
		}
		wantUntil := base.Add(5 * time.Minute)
		if !err.LockedUntil.Equal(wantUntil) {
			t.Fatalf("锁定截止应为 %s，实际 %s", wantUntil, err.LockedUntil)
		}
		t.Logf("业务[节流锁定] 用例[达阈值锁定] 通过：3/3 失败，锁定至 %s", err.LockedUntil.Format(time.RFC3339))
	})

	t.Run("锁定期内继续尝试不延长锁定", func(t *testing.T) {
		clock.Advance(2 * time.Minute)
		th.RecordFailure("alice")
		_, until := th.State("alice")
		if !until.Equal(base.Add(5 * time.Minute)) {
			t.Fatalf("锁定截止不应被延长，实际 %s", until)
		}
		t.Logf("业务[节流锁定] 用例[锁定不延长] 通过：锁定期内失败仍锁定至 %s", until.Format(time.RFC3339))
	})

	t.Run("锁定期满自动恢复且计数清零", func(t *testing.T) {
		clock.Advance(4 * time.Minute) // 到达锁定截止时刻（第 6 分钟）
		if err := th.Check("alice"); err != nil {
			t.Fatalf("锁定期满应自动恢复，实际 %v", err)
		}
		failures, _ := th.State("alice")
		if failures != 0 {
			t.Fatalf("恢复后计数应清零，实际 %d", failures)
		}
		t.Logf("业务[节流锁定] 用例[到期自动恢复] 通过：锁定解除，计数清零")
	})

	t.Run("计数窗口外的旧失败不计入", func(t *testing.T) {
		th2 := NewThrottler(cfg, clock)
		th2.RecordFailure("carol")
		th2.RecordFailure("carol")
		clock.Advance(11 * time.Minute) // 超过 10 分钟计数窗口
		th2.RecordFailure("carol")
		failures, _ := th2.State("carol")
		if failures != 1 {
			t.Fatalf("窗口外旧失败应作废，期望计数 1，实际 %d", failures)
		}
		t.Logf("业务[节流锁定] 用例[计数窗口过期] 通过：2 次旧失败作废后重新计为 1")
	})

	t.Run("成功登录清空计数", func(t *testing.T) {
		th.RecordSuccess("alice")
		failures, _ := th.State("alice")
		if failures != 0 {
			t.Fatalf("成功后计数应为 0，实际 %d", failures)
		}
		t.Logf("业务[节流锁定] 用例[成功清零] 通过")
	})

	t.Run("按身份维度独立计数", func(t *testing.T) {
		th3 := NewThrottler(cfg, &FixedClock{T: base})
		for i := 0; i < 3; i++ {
			th3.RecordFailure("locked-user")
		}
		if err := th3.Check("locked-user"); err == nil {
			t.Fatal("locked-user 应已锁定")
		}
		if err := th3.Check("other-user"); err != nil {
			t.Fatalf("other-user 不应受牵连，实际 %v", err)
		}
		t.Logf("业务[节流锁定] 用例[身份维度隔离] 通过：一人锁定不影响他人")
	})
}

// TestThrottleConcurrentCounting 业务：并发失败计数必须准确，不多不少。
func TestThrottleConcurrentCounting(t *testing.T) {
	clock := &FixedClock{T: time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)}
	cfg := ThrottleConfig{MaxFailures: 100, Window: time.Minute, Lockout: time.Minute}
	th := NewThrottler(cfg, clock)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			th.RecordFailure("sam")
		}()
	}
	wg.Wait()

	failures, _ := th.State("sam")
	if failures != n {
		t.Fatalf("并发计数应为 %d，实际 %d", n, failures)
	}
	t.Logf("业务[并发计数准确] 用例[%d 个并发失败无一丢失] 通过：count=%d，未触发锁定", n, failures)
}
