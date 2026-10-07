package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// DefaultSessionTTL 是会话默认有效期。
const DefaultSessionTTL = 30 * time.Minute

// Service 把用户、会话、RBAC 与限流组合成本地认证授权门面。
type Service struct {
	users     *UserStore
	sessions  *SessionStore
	rbac      *RBAC
	throttler *Throttler
	clock     Clock
}

// NewService 创建认证授权服务。
func NewService(users *UserStore, sessions *SessionStore, rbac *RBAC, throttler *Throttler, clock Clock) *Service {
	if clock == nil {
		clock = RealClock{}
	}
	return &Service{
		users:     users,
		sessions:  sessions,
		rbac:      rbac,
		throttler: throttler,
		clock:     clock,
	}
}

// HashPassword 生成口令摘要。本地演示使用 SHA-256；
// 生产系统应替换为 bcrypt/argon2 等慢哈希。
func HashPassword(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// Login 校验账密并签发会话令牌。
//
// 对“账号不存在”和“密码错误”统一返回 ErrInvalidCredential，
// 避免通过响应差异泄露账号是否存在；两类失败同样计入节流。
func (s *Service) Login(username, password string) (string, *RejectError) {
	if err := s.throttler.Check(username); err != nil {
		return "", err
	}

	u := s.users.FindByUsername(username)
	// 无论用户是否存在都计算一次摘要，减少基于耗时的用户枚举。
	hash := HashPassword(password)
	ok := u != nil && subtleEqual(u.PasswordHash, hash)
	if !ok {
		s.throttler.RecordFailure(username)
		return "", ErrInvalidCredential
	}

	s.throttler.RecordSuccess(username)
	tok, _ := s.sessions.Issue(u)
	return tok.Raw, nil
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Authenticate 仅校验凭证并返回有效会话；
// 可区分：篡改(malformed)、未知(unknown)、已失效(revoked)、已过期(expired)。
func (s *Service) Authenticate(rawToken string) (*Session, *RejectError) {
	tok, err := s.sessions.Parse(rawToken)
	if err != nil {
		return nil, err
	}
	return s.sessions.Validate(tok)
}

// Authorize 校验凭证并检查权限：
// 未认证返回具体凭证原因；已认证但无权限返回 ReasonForbidden。
func (s *Service) Authorize(rawToken, permission string) (*Session, *RejectError) {
	sess, err := s.Authenticate(rawToken)
	if err != nil {
		return nil, err
	}
	if !s.rbac.HasPermission(sess.Username, permission) {
		return nil, &RejectError{
			Reason:  ReasonForbidden,
			Message: "missing required permission: " + permission,
		}
	}
	return sess, nil
}

// Renew 为持有的会话续期；令牌值保持不变，可继续使用。
func (s *Service) Renew(rawToken string) (string, *RejectError) {
	tok, err := s.sessions.Parse(rawToken)
	if err != nil {
		return "", err
	}
	if _, err := s.sessions.Renew(tok, s.sessions.ttl); err != nil {
		return "", err
	}
	return rawToken, nil
}

// Logout 主动失效会话；幂等。
func (s *Service) Logout(rawToken string) *RejectError {
	tok, err := s.sessions.Parse(rawToken)
	if err != nil {
		return err
	}
	return s.sessions.Revoke(tok)
}
