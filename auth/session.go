package auth

import (
	"sync"
	"time"
)

// Session 是服务端保存的会话权威记录。令牌只是对它的签名引用。
type Session struct {
	ID        string
	Username  string
	CreatedAt time.Time
	// ExpiresAt 为绝对过期时刻；到点即失效。
	ExpiresAt time.Time
	// IdleDeadline 为空闲超时时刻；每次校验或续期向后滑动。
	IdleDeadline time.Time
	// RenewedAt 记录当前这一代会话最近一次续期发生的时刻，
	// 未续期时等于 CreatedAt（仅用于记录/展示，不作为代际判据）。
	RenewedAt time.Time
	// Generation 是单调递增的会话代际：创建时为 1，每次成功续期 +1。
	// 用它而非时间戳识别并发重复续期，避免同一时刻内多次续期无法区分。
	Generation int64
	Revoked    bool
}

// ExpiredAt 返回该会话在 now 视角下是否已不可用，
// 以及不可用的原因（绝对过期 / 空闲过期统一归为会话过期）。
func (s *Session) ExpiredAt(now time.Time) (bool, Reason) {
	if !now.Before(s.ExpiresAt) {
		return true, ReasonSessionExpired
	}
	if !now.Before(s.IdleDeadline) {
		return true, ReasonSessionExpired
	}
	return false, ""
}

// SessionStore 以内存方式保存会话，所有方法在并发下安全。
// 会话的“代际”由 RenewedAt 标识：一次成功续期推进一代，
// 旧代令牌在续期竞争中会被 CAS 拒绝，从而杜绝重复续期。
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// NewSessionStore 创建空会话存储。
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: map[string]*Session{}}
}

// Put 写入一条会话（覆盖同 ID 旧记录）。
func (s *SessionStore) Put(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := sess
	s.sessions[sess.ID] = &cp
}

// Get 读取会话副本；不存在时 ok 为 false。
func (s *SessionStore) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	return *p, true
}

// Delete 移除一条会话，返回是否真的移除过。
func (s *SessionStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return false
	}
	delete(s.sessions, id)
	return true
}

// Touch 在会话仍存活时把空闲截止时间向后滑动到 now+idleTTL，
// 只前进不回退；供每次成功校验调用。已失效/过期会话返回 false。
func (s *SessionStore) Touch(id string, now time.Time, idleTTL time.Duration) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.sessions[id]
	if !ok || p.Revoked {
		return Session{}, false
	}
	if expired, _ := p.ExpiredAt(now); expired {
		return *p, false
	}
	newDeadline := now.Add(idleTTL)
	if newDeadline.After(p.IdleDeadline) {
		p.IdleDeadline = newDeadline
	}
	return *p, true
}

// CompareAndSwapRenew 以 CAS 方式续期：仅当会话存在、未失效、未过期且
// 当前 Generation 等于 expectGeneration 时，才把代际 +1 并滑动空闲截止时间。
// 整个“检查 + 更新”在同一把锁内完成，并发续期只有一代能成功，
// 其余代（旧令牌或同一旧令牌的重复请求）返回 false。
func (s *SessionStore) CompareAndSwapRenew(id string, expectGeneration int64, now time.Time, idleTTL time.Duration) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.sessions[id]
	if !ok || p.Revoked {
		return Session{}, false
	}
	if expired, _ := p.ExpiredAt(now); expired {
		return *p, false
	}
	if p.Generation != expectGeneration {
		return *p, false
	}
	p.Generation++
	p.RenewedAt = now
	p.IdleDeadline = now.Add(idleTTL)
	return *p, true
}

// CompareAndSwapRevoke 以 CAS 方式失效会话：仅当尚未失效时置 Revoked。
// 重复或并发失效返回 false，调用方可据此幂等处理，状态始终确定。
func (s *SessionStore) CompareAndSwapRevoke(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if p.Revoked {
		return *p, false
	}
	p.Revoked = true
	return *p, true
}

// Len 返回当前会话数量（测试辅助）。
func (s *SessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}
