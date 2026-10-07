package auth

import "sync"

// User 是本地内存中的用户记录。
type User struct {
	Username     string
	PasswordHash string
	Roles        []string
	// extraPerms 是直接授予该用户个人的权限位，与角色权限取并集。
	// 角色或此处任一调整都会在后续鉴权中立即生效。
	extraPerms map[string]bool
}

// Role 描述一个角色及其持有的权限集合。
type Role struct {
	Name        string
	Permissions map[string]bool
}

// UserStore 以内存方式保存用户与角色。用户和角色调整后，
// 所有后续鉴权立即看到最新状态，不存在权限快照缓存。
type UserStore struct {
	mu    sync.RWMutex
	users map[string]User
	roles map[string]Role
}

// NewUserStore 创建空的用户/角色存储。
func NewUserStore() *UserStore {
	return &UserStore{users: map[string]User{}, roles: map[string]Role{}}
}

// cloneUser 返回用户的副本（含切片与 map 的拷贝），避免调用方改到内部状态。
func cloneUser(u User) User {
	roles := make([]string, len(u.Roles))
	copy(roles, u.Roles)
	perms := make(map[string]bool, len(u.extraPerms))
	for k, v := range u.extraPerms {
		perms[k] = v
	}
	u.Roles = roles
	u.extraPerms = perms
	return u
}

// AddUser 写入或覆盖一个用户。
func (s *UserStore) AddUser(u User) {
	if u.extraPerms == nil {
		u.extraPerms = map[string]bool{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Username] = cloneUser(u)
}

// GetUser 按用户名读取用户；不存在时 ok 为 false。
func (s *UserStore) GetUser(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return User{}, false
	}
	return cloneUser(u), true
}

// AddRole 写入或覆盖一个角色。
func (s *UserStore) AddRole(r Role) {
	if r.Permissions == nil {
		r.Permissions = map[string]bool{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	perms := make(map[string]bool, len(r.Permissions))
	for k, v := range r.Permissions {
		perms[k] = v
	}
	r.Permissions = perms
	s.roles[r.Name] = r
}

// GetRole 按名称读取角色。
func (s *UserStore) GetRole(name string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[name]
	if !ok {
		return Role{}, false
	}
	perms := make(map[string]bool, len(r.Permissions))
	for k, v := range r.Permissions {
		perms[k] = v
	}
	r.Permissions = perms
	return r, true
}

// updateUser 在写锁内对用户做一次变更；用户不存在返回错误。
func (s *UserStore) updateUser(username string, fn func(*User)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return NewError(ReasonUserNotFound, "user not found: "+username)
	}
	fn(&u)
	s.users[username] = u
	return nil
}

// GrantRole 为用户追加角色（已存在则幂等）。
func (s *UserStore) GrantRole(username, role string) error {
	return s.updateUser(username, func(u *User) {
		for _, r := range u.Roles {
			if r == role {
				return
			}
		}
		u.Roles = append(u.Roles, role)
	})
}

// RevokeRole 移除用户的某个角色。
func (s *UserStore) RevokeRole(username, role string) error {
	return s.updateUser(username, func(u *User) {
		kept := u.Roles[:0]
		for _, r := range u.Roles {
			if r != role {
				kept = append(kept, r)
			}
		}
		u.Roles = kept
	})
}

// UserPermission 直接为用户附加/摘除一个个人权限位。
func (s *UserStore) UserPermission(username string, permission string, granted bool) error {
	return s.updateUser(username, func(u *User) {
		if u.extraPerms == nil {
			u.extraPerms = map[string]bool{}
		}
		if granted {
			u.extraPerms[permission] = true
		} else {
			delete(u.extraPerms, permission)
		}
	})
}

// HasPermission 判断用户当前（实时）是否持有某权限。
// 判定在一次 RLock 内完成：读取角色集合 + 逐角色查权限 + 个人权限，
// 因此与 GrantRole/RevokeRole/AddRole 等变更串行，不会读到半更新状态。
func (s *UserStore) HasPermission(username, permission string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return false
	}
	if u.extraPerms[permission] {
		return true
	}
	for _, roleName := range u.Roles {
		if role, ok := s.roles[roleName]; ok {
			if role.Permissions[permission] {
				return true
			}
		}
	}
	return false
}

// RolesOf 返回用户当前的角色快照（测试辅助）。
func (s *UserStore) RolesOf(username string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, false
	}
	out := make([]string, len(u.Roles))
	copy(out, u.Roles)
	return out, true
}
