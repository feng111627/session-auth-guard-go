package auth

import "sync"

// User 是本地用户档案，角色决定其权限集合。
// 密码以摘要形式存储（演示使用 SHA-256）。
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Roles        []string
}

// UserStore 是用户与角色的内存存储。
// 所有读写均在锁保护下进行；角色调整对后续所有检查即时可见。
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User // 以用户名为主键
}

// NewUserStore 创建空的用户存储。
func NewUserStore() *UserStore {
	return &UserStore{users: make(map[string]*User)}
}

// AddUser 登记一个用户；内部保存副本，避免外部后续修改绕过锁。
func (s *UserStore) AddUser(u *User) {
	if u == nil {
		return
	}
	stored := *u
	stored.Roles = append([]string(nil), u.Roles...)
	s.mu.Lock()
	s.users[u.Username] = &stored
	s.mu.Unlock()
}

// FindByUsername 按用户名查找用户；未找到返回 nil。
// 返回内部指针的只读使用约定：调用方不得修改。
func (s *UserStore) FindByUsername(username string) *User {
	s.mu.RLock()
	u := s.users[username]
	s.mu.RUnlock()
	return u
}

// SnapshotRoles 返回用户当前角色的副本；用户不存在时返回 nil。
func (s *UserStore) SnapshotRoles(username string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, false
	}
	return append([]string(nil), u.Roles...), true
}

// SetRoles 整体替换用户的角色集合，调整对既有会话的后续请求立即生效。
func (s *UserStore) SetRoles(username string, roles []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return false
	}
	u.Roles = append([]string(nil), roles...)
	return true
}
