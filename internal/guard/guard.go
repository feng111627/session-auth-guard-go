package guard

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/feng111627/session-auth-guard-go/internal/auth"
)

// Decision 是入口层对一次请求的结论。
type Decision struct {
	Allowed bool              `json:"allowed"`
	Reason  auth.RejectReason `json:"reason,omitempty"`
	Message string            `json:"message,omitempty"`
	Session *auth.Session     `json:"-"`
}

// Entry 是绑定了某个权限要求的访问入口。
// permission 为空时只要求“已登录”；非空时还要求对应权限。
type Entry struct {
	svc        *auth.Service
	permission string
}

// New 创建入口。
func New(svc *auth.Service, permission string) *Entry {
	return &Entry{svc: svc, permission: permission}
}

// Check 对原始令牌做认证（可选授权）并返回统一结论：
// 无令牌 -> unauthenticated；凭证问题 -> 对应凭证原因；
// 已登录但无权限 -> forbidden，两者可明确区分。
func (e *Entry) Check(rawToken string) Decision {
	if strings.TrimSpace(rawToken) == "" {
		return Decision{Reason: auth.ReasonUnauthenticated, Message: "authentication required"}
	}
	var (
		sess *auth.Session
		err  *auth.RejectError
	)
	if e.permission == "" {
		sess, err = e.svc.Authenticate(rawToken)
	} else {
		sess, err = e.svc.Authorize(rawToken, e.permission)
	}
	if err != nil {
		return Decision{Reason: err.Reason, Message: err.Message}
	}
	return Decision{Allowed: true, Session: sess}
}

// statusFor 把拒绝原因映射为稳定的 HTTP 状态码。
func statusFor(r auth.RejectReason) int {
	switch r {
	case auth.ReasonForbidden:
		return http.StatusForbidden
	case auth.ReasonTooManyAttempts:
		return http.StatusTooManyRequests
	default:
		// malformed / unknown / revoked / expired / unauthenticated / invalid credential
		return http.StatusUnauthorized
	}
}

// bearerToken 从 Authorization 头提取 Bearer 令牌。
func bearerToken(h http.Header) string {
	v := h.Get("Authorization")
	if v == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return ""
}

// Middleware 以 HTTP 中间件形式执行检查，
// 拒绝时写入与原因一致的状态码以及可解释的 JSON 正文。
func (e *Entry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := e.Check(bearerToken(r.Header))
		if !d.Allowed {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(statusFor(d.Reason))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"allowed": false,
				"reason":  string(d.Reason),
				"message": d.Message,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
