package auth

import "testing"

// TestRBACPermissionChange 业务：基于角色的访问控制与即时生效。
func TestRBACPermissionChange(t *testing.T) {
	users := NewUserStore()
	users.AddUser(&User{ID: "u1", Username: "alice", Roles: []string{"member"}})
	users.AddUser(&User{ID: "u2", Username: "bob", Roles: []string{"viewer"}})

	rbac := NewRBAC(func(name string) []string {
		roles, _ := users.SnapshotRoles(name)
		return roles
	})
	rbac.GrantRole("member", "doc:read")
	rbac.GrantRole("admin", "doc:read", "doc:write", "user:manage")

	t.Run("有角色权限则允许", func(t *testing.T) {
		if !rbac.HasPermission("alice", "doc:read") {
			t.Fatal("alice 应持有 doc:read")
		}
		t.Logf("业务[RBAC] 用例[成员可读文档] 通过：alice(member) -> doc:read 允许")
	})

	t.Run("无权限返回禁止结论（与未认证区分由上层保证）", func(t *testing.T) {
		if rbac.HasPermission("alice", "doc:write") {
			t.Fatal("alice 不应持有 doc:write")
		}
		if rbac.HasPermission("bob", "doc:read") {
			t.Fatal("viewer 未被授予 doc:read，应拒绝")
		}
		t.Logf("业务[RBAC] 用例[越权拒绝] 通过：alice 写文档、bob 读文档均拒绝")
	})

	t.Run("角色新增权限对后续请求立即生效", func(t *testing.T) {
		rbac.GrantRole("member", "doc:write")
		if !rbac.HasPermission("alice", "doc:write") {
			t.Fatal("授权后 alice 应立即持有 doc:write")
		}
		t.Logf("业务[RBAC] 用例[授予即时生效] 通过：member 增补 doc:write 后立即允许")
	})

	t.Run("角色回收权限即时生效，旧凭证不造成越权", func(t *testing.T) {
		rbac.RevokePermission("member", "doc:write")
		if rbac.HasPermission("alice", "doc:write") {
			t.Fatal("回收后 alice 不应再持有 doc:write（无缓存旧状态）")
		}
		t.Logf("业务[RBAC] 用例[回收即时生效] 通过：member 移除 doc:write 后立即拒绝")
	})

	t.Run("用户换角色即时生效", func(t *testing.T) {
		if !users.SetRoles("alice", []string{"admin"}) {
			t.Fatal("角色调整应成功")
		}
		if !rbac.HasPermission("alice", "user:manage") {
			t.Fatal("alice 升为 admin 后应立即持有 user:manage")
		}
		users.SetRoles("alice", []string{"member"})
		if rbac.HasPermission("alice", "user:manage") {
			t.Fatal("alice 降回 member 后不应再持有 user:manage")
		}
		t.Logf("业务[RBAC] 用例[用户换角色即时生效] 通过：升 admin / 降 member 均立刻反映")
	})

	t.Run("未知用户无任何权限", func(t *testing.T) {
		if rbac.HasPermission("ghost", "doc:read") {
			t.Fatal("不存在的用户不应有权限")
		}
		t.Logf("业务[RBAC] 用例[未知用户无权限] 通过")
	})
}
