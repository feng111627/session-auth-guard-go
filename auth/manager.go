package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// ManagerConfig 控制会话生命周期时长。
type ManagerConfig struct {
	// AbsoluteTTL 绝对寿命：从创建起超过该时长必定过期。
	AbsoluteTTL time.Duration
	// IdleTTL 空闲寿命：距上次活动超过该时长即过期。
	IdleTTL time.Duration
}

// SessionManager 编排会话的创建、校验、续期与主动失效。
type SessionManager struct {
	store  *SessionStore
	codec  *TokenCodec
	clock  Clock
	config ManagerConfig
}

// NewSessionManager 创建会话管理器。
func NewSessionManager(store *SessionStore, codec *TokenCodec, clock Clock, config ManagerConfig) *SessionManager {
	return &SessionManager{store: store, codec: codec, clock: clock, config: config}
}

func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败在常规环境下不可恢复，直接 panic 暴露环境问题。
		panic("auth: cannot read random bytes: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Create 为用户新建会话并返回签发令牌。
func (m *SessionManager) Create(username string) (string, error) {
	if username == "" {
		return "", NewError(ReasonInvalidCredentials, "empty username")
	}
	now := m.clock.Now()
	sess := Session{
		ID:           newSessionID(),
		Username:     username,
		CreatedAt:    now,
		ExpiresAt:    now.Add(m.config.AbsoluteTTL),
		IdleDeadline: now.Add(m.config.IdleTTL),
		RenewedAt:    now,
		Generation:   1,
	}
	m.store.Put(sess)
	return m.codec.Issue(TokenClaims{
		SessionID:  sess.ID,
		Username:   sess.Username,
		Generation: sess.Generation,
		ExpiresAt:  sess.ExpiresAt,
	}), nil
}

// Validate 校验令牌并返回当前会话；按真实原因区分
// 无凭证/格式错/签名错/会话不存在/过期/已失效等结论。
// 校验成功会把空闲截止时间向后滑动。
func (m *SessionManager) Validate(token string) (Session, error) {
	if token == "" {
		return Session{}, NewError(ReasonNoCredentials, "missing token")
	}
	claims, err := m.codec.Parse(token)
	if err != nil {
		return Session{}, err
	}
	sess, ok := m.store.Get(claims.SessionID)
	if !ok {
		return Session{}, NewError(ReasonSessionNotFound, "session no longer exists")
	}
	if sess.Revoked {
		return Session{}, NewError(ReasonSessionRevoked, "session has been revoked")
	}
	if expired, reason := sess.ExpiredAt(m.clock.Now()); expired {
		return Session{}, NewError(reason, "session has expired")
	}
	// 成功活动：滑动空闲窗口。Touch 只在仍存活时生效。
	if touched, ok := m.store.Touch(sess.ID, m.clock.Now(), m.config.IdleTTL); ok {
		sess = touched
	}
	return sess, nil
}

// Renew 用旧令牌续期：同一会话同一代只允许一次成功续期，
// 并发或重复续期返回 ReasonDuplicateRenewal，成功则签发新令牌。
func (m *SessionManager) Renew(token string) (string, Session, error) {
	if token == "" {
		return "", Session{}, NewError(ReasonNoCredentials, "missing token")
	}
	claims, err := m.codec.Parse(token)
	if err != nil {
		return "", Session{}, err
	}
	now := m.clock.Now()
	sess, ok := m.store.CompareAndSwapRenew(claims.SessionID, claims.Generation, now, m.config.IdleTTL)
	if !ok {
		// CAS 失败需要给出可区分原因：重新读取权威记录判断。
		cur, exists := m.store.Get(claims.SessionID)
		switch {
		case !exists:
			return "", Session{}, NewError(ReasonSessionNotFound, "session no longer exists")
		case cur.Revoked:
			return "", Session{}, NewError(ReasonSessionRevoked, "session has been revoked")
		case func() bool { e, _ := cur.ExpiredAt(now); return e }():
			return "", Session{}, NewError(ReasonSessionExpired, "session has expired")
		default:
			// 代际不匹配：该令牌对应的这一代已被续期过。
			return "", Session{}, NewError(ReasonDuplicateRenewal, "this token generation was already renewed")
		}
	}
	newToken := m.codec.Issue(TokenClaims{
		SessionID:  sess.ID,
		Username:   sess.Username,
		Generation: sess.Generation,
		ExpiresAt:  sess.ExpiresAt,
	})
	return newToken, sess, nil
}

// Revoke 主动失效令牌对应的会话；对已失效会话重复调用是幂等的。
func (m *SessionManager) Revoke(token string) error {
	if token == "" {
		return NewError(ReasonNoCredentials, "missing token")
	}
	claims, err := m.codec.Parse(token)
	if err != nil {
		return err
	}
	return m.RevokeSession(claims.SessionID)
}

// RevokeSession 按会话 ID 主动失效（供登出之外的管理用途）。
// 会话不存在返回 ReasonSessionNotFound；重复失效幂等成功。
func (m *SessionManager) RevokeSession(sessionID string) error {
	sess, ok := m.store.Get(sessionID)
	if !ok {
		return NewError(ReasonSessionNotFound, "session no longer exists")
	}
	if sess.Revoked {
		return nil
	}
	if _, swapped := m.store.CompareAndSwapRevoke(sessionID); !swapped {
		// 并发失效竞争落败，对方已置位，语义上仍是已失效，幂等返回。
		return nil
	}
	return nil
}
