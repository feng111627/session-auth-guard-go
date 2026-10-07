package auth

import "time"

// RejectReason 描述凭证或访问被拒绝的具体类别，
// 让调用方能够区分不同的失败原因。
type RejectReason string

const (
	ReasonNone              RejectReason = ""
	ReasonMalformedToken    RejectReason = "malformed_token"
	ReasonUnknownSession    RejectReason = "unknown_session"
	ReasonRevokedSession    RejectReason = "revoked_session"
	ReasonExpiredSession    RejectReason = "expired_session"
	ReasonInvalidCredential RejectReason = "invalid_credential"
	ReasonTooManyAttempts   RejectReason = "too_many_attempts"
	ReasonUnauthenticated   RejectReason = "unauthenticated"
	ReasonForbidden         RejectReason = "forbidden"
)

// RejectError 携带一个结构化的拒绝原因。
type RejectError struct {
	Reason      RejectReason
	Message     string
	LockedUntil time.Time // 仅 ReasonTooManyAttempts 时有效
}

// Error 实现 error。
func (e *RejectError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// ErrInvalidCredential 对“账号不存在”和“密码错误”统一返回的错误，
// 避免对外泄露账号是否存在。
var ErrInvalidCredential = &RejectError{
	Reason:  ReasonInvalidCredential,
	Message: "invalid username or password",
}
