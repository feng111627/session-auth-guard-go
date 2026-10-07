package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

// Session 是服务端会话记录，令牌本身不携带状态，一切以服务端记录为准。
type Session struct {
	ID        string
	UserID    string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
	Version   int64 // 每次成功续期自增
}

// Alive 判断会话在 now 时刻是否既未过期也未被失效。
func (s *Session) Alive(now time.Time) bool {
	return !s.Revoked && now.Before(s.ExpiresAt)
}

// Token 是发给客户端的凭证：会话标识 + 针对标识的 HMAC 签名。
// 篡改标识或签名都会在校验时被发现。
type Token struct {
	Raw       string
	SessionID string
	Sig       string
}

var b64 = base64.RawURLEncoding

// renewCall 表示一次进行中的续期，用于并发请求合并（singleflight）。
type renewCall struct {
	done chan struct{}
	sess *Session
	err  *RejectError
}

// SessionStore 管理会话记录与令牌签发/校验。
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	renewing map[string]*renewCall
	secret   []byte
	ttl      time.Duration
	clock    Clock
	// renewHook 仅供测试：由续期 leader 在登记 singleflight 之后、
	// 真正执行续期之前调用，可用于把一批并发请求确定性地拦在同一轮里。
	renewHook func()
	// waitHook 仅供测试：跟随者确认已有进行中的续期、即将等待时调用。
	waitHook func()
}

// NewSessionStore 创建会话存储。
func NewSessionStore(secret []byte, ttl time.Duration, clock Clock) *SessionStore {
	if clock == nil {
		clock = RealClock{}
	}
	return &SessionStore{
		sessions: make(map[string]*Session),
		renewing: make(map[string]*renewCall),
		secret:   append([]byte(nil), secret...),
		ttl:      ttl,
		clock:    clock,
	}
}

func (s *SessionStore) sign(sessionID string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(sessionID))
	return b64.EncodeToString(m.Sum(nil))
}

func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败极不寻常；退回时间熵并仍然返回标识。
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return b64.EncodeToString(b[:])
}

// Issue 为用户创建新会话并返回签名令牌。
func (s *SessionStore) Issue(u *User) (*Token, *Session) {
	now := s.clock.Now()
	id := newSessionID()
	sess := &Session{
		ID:        id,
		UserID:    u.ID,
		Username:  u.Username,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	raw := b64.EncodeToString([]byte(id)) + "." + s.sign(id)
	tok := &Token{Raw: raw, SessionID: id, Sig: s.sign(id)}

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	// 返回副本，避免调用方持有并修改内部记录。
	return tok, cloneSession(sess)
}

// Parse 解析令牌结构并重算签名：
// 结构非法或签名不匹配一律归因为 malformed_token（被篡改/伪造）。
func (s *SessionStore) Parse(raw string) (*Token, *RejectError) {
	id, sig, ok := splitToken(raw)
	if !ok {
		return nil, &RejectError{Reason: ReasonMalformedToken, Message: "malformed token"}
	}
	want := s.sign(id)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return nil, &RejectError{Reason: ReasonMalformedToken, Message: "token signature mismatch"}
	}
	return &Token{Raw: raw, SessionID: id, Sig: sig}, nil
}

func splitToken(raw string) (id, sig string, ok bool) {
	dot := -1
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot == len(raw)-1 {
		return "", "", false
	}
	idEnc, sigEnc := raw[:dot], raw[dot+1:]
	idBytes, err := b64.DecodeString(idEnc)
	if err != nil {
		return "", "", false
	}
	if _, err := b64.DecodeString(sigEnc); err != nil {
		return "", "", false
	}
	return string(idBytes), sigEnc, true
}

func sessionByID(sess *Session, now time.Time) *RejectError {
	switch {
	case sess == nil:
		return &RejectError{Reason: ReasonUnknownSession, Message: "session not found"}
	case sess.Revoked:
		return &RejectError{Reason: ReasonRevokedSession, Message: "session has been revoked"}
	case !now.Before(sess.ExpiresAt):
		return &RejectError{Reason: ReasonExpiredSession, Message: "session expired"}
	}
	return nil
}

// Validate 校验令牌对应会话是否可用，并给出区分性结论。
func (s *SessionStore) Validate(t *Token) (*Session, *RejectError) {
	now := s.clock.Now()
	s.mu.Lock()
	sess := s.sessions[t.SessionID]
	err := sessionByID(sess, now)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	cp := *sess
	return &cp, nil
}

// Renew 为会话续期 extend 时长。
// 对同一会话的并发续期会被合并为一次实际续期（singleflight），
// 因此不会出现重复叠加有效期；与 Revoke 并发时由同一把锁决定先后。
func (s *SessionStore) Renew(t *Token, extend time.Duration) (*Session, *RejectError) {
	s.mu.Lock()
	if call, ok := s.renewing[t.SessionID]; ok {
		s.mu.Unlock()
		if s.waitHook != nil {
			s.waitHook()
		}
		<-call.done
		return cloneSession(call.sess), call.err
	}
	call := &renewCall{done: make(chan struct{})}
	s.renewing[t.SessionID] = call
	s.mu.Unlock()

	// 钩子期间不持锁，使并发请求能够进入排队分支。
	if s.renewHook != nil {
		s.renewHook()
	}

	defer func() {
		s.mu.Lock()
		delete(s.renewing, t.SessionID)
		s.mu.Unlock()
		close(call.done)
	}()

	now := s.clock.Now()
	s.mu.Lock()
	sess := s.sessions[t.SessionID]
	if err := sessionByID(sess, now); err != nil {
		s.mu.Unlock()
		call.err = err
		return nil, err
	}
	sess.ExpiresAt = now.Add(extend)
	sess.Version++
	cp := *sess
	s.mu.Unlock()

	call.sess = &cp
	return &cp, nil
}

// Revoke 主动失效会话，重复失效保持幂等；
// 失效一旦返回，后续 Validate/Renew 必然得到 revoked 结论。
func (s *SessionStore) Revoke(t *Token) *RejectError {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[t.SessionID]
	if !ok {
		return &RejectError{Reason: ReasonUnknownSession, Message: "session not found"}
	}
	sess.Revoked = true
	return nil
}

func cloneSession(s *Session) *Session {
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}
