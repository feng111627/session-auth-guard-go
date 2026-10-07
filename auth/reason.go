package auth

import "net/http"

// Reason 以可区分的结论描述一次请求为何被接受或拒绝。
type Reason string

const (
	// ReasonOK 请求通过。
	ReasonOK Reason = "ok"
	// ReasonNoCredentials 请求未携带任何凭证。
	ReasonNoCredentials Reason = "no_credentials"
	// ReasonMalformedToken 令牌格式非法或无法解码。
	ReasonMalformedToken Reason = "malformed_token"
	// ReasonBadSignature 令牌签名与本机密钥不匹配（疑似篡改）。
	ReasonBadSignature Reason = "bad_signature"
	// ReasonSessionNotFound 令牌指向的会话不存在。
	ReasonSessionNotFound Reason = "session_not_found"
	// ReasonSessionExpired 会话绝对寿命或空闲超时已到期。
	ReasonSessionExpired Reason = "session_expired"
	// ReasonSessionRevoked 会话已被主动失效。
	ReasonSessionRevoked Reason = "session_revoked"
	// ReasonDuplicateRenewal 该版本的会话已被并发续期过一次，本次续期重复。
	ReasonDuplicateRenewal Reason = "duplicate_renewal"
	// ReasonPermissionDenied 已认证，但角色不具备所需权限。
	ReasonPermissionDenied Reason = "permission_denied"
	// ReasonInvalidCredentials 用户名不存在或密码错误（对外统一结论）。
	ReasonInvalidCredentials Reason = "invalid_credentials"
	// ReasonThrottled 失败尝试过多，当前处于节流窗口。
	ReasonThrottled Reason = "throttled"
	// ReasonLocked 失败次数达到阈值，账号当前被锁定。
	ReasonLocked Reason = "locked"
	// ReasonUserNotFound 管理操作的目标用户不存在（内部错误，非认证结论）。
	ReasonUserNotFound Reason = "user_not_found"
)

// AuthError 携带可解释结论的错误。
type AuthError struct {
	Reason  Reason
	Message string
}

func (e *AuthError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return string(e.Reason) + ": " + e.Message
	}
	return string(e.Reason)
}

// NewError 用给定结论与描述构造错误。
func NewError(r Reason, msg string) *AuthError {
	return &AuthError{Reason: r, Message: msg}
}

// Decision 是两个入口（服务 API 与 HTTP 中间件）共用的判定结论。
type Decision struct {
	Allowed  bool
	Reason   Reason
	Username string
}

// HTTPStatus 把结论映射为可解释的 HTTP 状态码。
func (d Decision) HTTPStatus() int {
	switch d.Reason {
	case ReasonOK:
		return http.StatusOK
	case ReasonNoCredentials, ReasonMalformedToken, ReasonBadSignature,
		ReasonSessionNotFound, ReasonSessionExpired, ReasonSessionRevoked:
		return http.StatusUnauthorized
	case ReasonPermissionDenied:
		return http.StatusForbidden
	case ReasonInvalidCredentials:
		return http.StatusUnauthorized
	case ReasonThrottled, ReasonLocked:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}
