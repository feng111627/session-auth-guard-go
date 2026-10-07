package auth

import (
	"testing"
	"time"
)

// caseLog 统一打印“业务 / 用例 / 结论”，配合 go test -v 可直观看到
// 覆盖了哪些业务以及每个用例的测试情况。
func caseLog(t *testing.T, business, name, result string) {
	t.Helper()
	t.Logf("[业务=%s] 用例=%s => %s", business, name, result)
}

// reasonIs 断言错误携带的可解释结论等于 want。
func reasonIs(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望错误结论 %q，实际为 nil", want)
	}
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("期望 *AuthError，实际为 %T: %v", err, err)
	}
	if ae.Reason != want {
		t.Fatalf("期望结论 %q，实际 %q（%v）", want, ae.Reason, err)
	}
}

// fixedNow 为测试提供一个确定的起点。
func fixedNow() time.Time {
	return time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
}

// newTestManager 构造使用假时钟的会话管理器。
func newTestManager(abs, idle time.Duration) (*SessionManager, *FakeClock) {
	clock := NewFakeClock(fixedNow())
	store := NewSessionStore()
	codec := NewTokenCodec([]byte("unit-test-secret"))
	m := NewSessionManager(store, codec, clock, ManagerConfig{AbsoluteTTL: abs, IdleTTL: idle})
	return m, clock
}

// tamperSignature 在 base64url 字母表内翻转令牌签名段的第一个字符，
// 构造“结构合法但签名不匹配”的篡改令牌。翻转首字符改变的是解码后
// 第一个完整字节；不能翻末位——Raw base64 末位可能落在无效填充位。
func tamperSignature(token string) string {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 || dot+1 >= len(token) {
		return token
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alter := func(c byte) byte {
		for i := 0; i < len(alphabet); i++ {
			if alphabet[i] == c {
				return alphabet[(i+1)%len(alphabet)]
			}
		}
		return c
	}
	c := alter(token[dot+1])
	return token[:dot+1] + string(c) + token[dot+2:]
}
