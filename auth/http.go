package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// principalContextKey 是身份在请求上下文中的键类型。
type principalContextKey struct{}

// Middleware 提供 HTTP 入口，把 Authorization: Bearer <token>
// 统一翻译为与 API 入口相同的 Reason 结论与 HTTP 状态码，
// 使未登录 / 已登录无权限 / 触发节流等请求在两个入口下结论一致。
type Middleware struct {
	service    *Service
	permission string
}

// NewMiddleware 创建要求指定权限的 HTTP 中间件。
// permission 为空时仅要求已认证。
func NewMiddleware(svc *Service, permission string) *Middleware {
	return &Middleware{service: svc, permission: permission}
}

// extractBearerToken 从请求头取出 Bearer 令牌；缺失返回空串。
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// Wrap 用该中间件包装受保护处理器。
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		var (
			p      Principal
			reason Reason
		)
		if m.permission == "" {
			p, reason = m.service.Authenticate(token)
		} else {
			p, reason = m.service.Authorize(token, m.permission)
		}
		if reason != ReasonOK {
			writeDecision(w, r, reason)
			return
		}
		ctx := ContextWithPrincipal(r.Context(), p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeDecision 把判定结论写为标准 JSON 响应，状态码与原因可解释。
func writeDecision(w http.ResponseWriter, _ *http.Request, reason Reason) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(Decision{Reason: reason}.HTTPStatus())
	_ = json.NewEncoder(w).Encode(map[string]string{
		"allowed": "false",
		"reason":  string(reason),
	})
}

// PrincipalFromContext 从上下文中读取已认证身份。
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

// ContextWithPrincipal 返回带身份的上下文（测试与扩展用）。
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}
