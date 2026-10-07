package auth

import "sync"

// RBAC 维护 角色 -> 权限 映射，并在每次鉴权时实时解析用户当前角色。
// 它不缓存任何用户级状态，因此角色/权限调整对既有会话立即生效。
type RBAC struct {
	mu           sync.RWMutex
	rolePerms    map[string]map[string]bool
	roleResolver func(identity string) []string
}

// NewRBAC 创建 RBAC 管理器；resolver 用于按身份（通常是用户名）
// 实时取回角色，nil 表示没有任何角色。
func NewRBAC(resolver func(identity string) []string) *RBAC {
	return &RBAC{
		rolePerms:    make(map[string]map[string]bool),
		roleResolver: resolver,
	}
}

// GrantRole 给角色授予若干权限（幂等，可重复调用增补）。
func (r *RBAC) GrantRole(role string, perms ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.rolePerms[role]
	if set == nil {
		set = make(map[string]bool)
		r.rolePerms[role] = set
	}
	for _, p := range perms {
		set[p] = true
	}
}

// RevokePermission 从角色移除权限；即时影响该角色下所有用户的后续请求。
func (r *RBAC) RevokePermission(role, perm string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if set, ok := r.rolePerms[role]; ok {
		delete(set, perm)
	}
}

// Roles 返回某角色当前持有的权限快照（主要用于观测/测试）。
func (r *RBAC) Roles(role string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := r.rolePerms[role]
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}

// HasPermission 按身份当前的角色集合判断是否持有某权限。
// 角色由 resolver 在调用当下解析，不依赖会话签发时的旧角色。
func (r *RBAC) HasPermission(identity string, perm string) bool {
	roles := []string(nil)
	if r.roleResolver != nil {
		roles = r.roleResolver(identity)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, role := range roles {
		if r.rolePerms[role] != nil && r.rolePerms[role][perm] {
			return true
		}
	}
	return false
}
