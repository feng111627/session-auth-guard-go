package auth

// Authorizer 在实时用户/角色状态上做 RBAC 判定。
// 它不缓存“会话 -> 权限”的任何快照：每次判定都实时读取 UserStore，
// 因此角色或权限调整对已建立的会话即时生效，旧状态无法造成越权。
type Authorizer struct {
	users *UserStore
}

// NewAuthorizer 创建鉴权器。
func NewAuthorizer(users *UserStore) *Authorizer {
	return &Authorizer{users: users}
}

// Can 判断用户当前是否持有某权限。
func (a *Authorizer) Can(username, permission string) bool {
	return a.users.HasPermission(username, permission)
}
