package auth

import (
	"testing"
	"time"
)

const businessRBAC = "基于角色的访问控制"

func newRBACService(t *testing.T) (*Service, *FakeClock) {
	t.Helper()
	clock := NewFakeClock(fixedNow())
	svc := NewServiceWithClock(ServiceConfig{
		TokenSecret: []byte("rbac-secret"),
		Sessions:    ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute},
		Throttle:    ThrottleConfig{MaxFailures: 5, Window: time.Minute, LockDuration: 10 * time.Second},
	}, clock)

	svc.Users().AddRole(Role{Name: "viewer", Permissions: map[string]bool{"doc:read": true}})
	svc.Users().AddRole(Role{Name: "editor", Permissions: map[string]bool{"doc:read": true, "doc:write": true}})
	svc.Users().AddUser(User{Username: "alice", PasswordHash: HashPassword("pw"), Roles: []string{"viewer"}})
	return svc, clock
}

func TestRBACUnauthenticatedVsForbidden(t *testing.T) {
	svc, _ := newRBACService(t)

	// 未携带凭证：未认证结论。
	if _, reason := svc.Authorize("", "doc:read"); reason != ReasonNoCredentials {
		t.Fatalf("无凭证应为 no_credentials，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "无凭证访问 => no_credentials(401)", "通过")

	token, _, err := svc.Login("alice", "pw")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	// 已认证但无 doc:write：明确的权限拒绝。
	if _, reason := svc.Authorize(token, "doc:write"); reason != ReasonPermissionDenied {
		t.Fatalf("无权限应为 permission_denied，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "已认证无权限 => permission_denied(403)", "通过")

	// 有权限：通过。
	if _, reason := svc.Authorize(token, "doc:read"); reason != ReasonOK {
		t.Fatalf("有权限应通过，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "持有权限 => ok(200)", "通过")
}

// TestRBACPermissionChangeImmediate 是关键场景：角色/权限调整后，
// 已建立的会话必须立即反映，旧令牌仍可用但不再越权。
func TestRBACPermissionChangeImmediate(t *testing.T) {
	svc, _ := newRBACService(t)
	token, _, err := svc.Login("alice", "pw")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	// 初始无写权限。
	if _, reason := svc.Authorize(token, "doc:write"); reason != ReasonPermissionDenied {
		t.Fatalf("初始应无写权限，实际 %s", reason)
	}

	// 提升为 editor：不重新登录，同一令牌立刻获得写权限（即时生效）。
	if err := svc.Users().GrantRole("alice", "editor"); err != nil {
		t.Fatalf("授予角色失败: %v", err)
	}
	if _, reason := svc.Authorize(token, "doc:write"); reason != ReasonOK {
		t.Fatalf("授权后同一令牌应立即可写，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "提权后存量会话立即生效(旧令牌仍可用)", "通过")

	// 角色权限被收窄：即时失去写权限，不能因缓存继续越权。
	svc.Users().AddRole(Role{Name: "editor", Permissions: map[string]bool{"doc:read": true}})
	if _, reason := svc.Authorize(token, "doc:write"); reason != ReasonPermissionDenied {
		t.Fatalf("角色收权后应立即拒绝，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "角色收权后存量会话立即拒绝(无越权)", "通过")

	// 直接摘除角色同样即时生效。
	if err := svc.Users().RevokeRole("alice", "editor"); err != nil {
		t.Fatalf("摘除角色失败: %v", err)
	}
	if _, reason := svc.Authorize(token, "doc:write"); reason != ReasonPermissionDenied {
		t.Fatalf("摘除角色后应无写权限，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "摘除角色即时生效", "通过")

	// 个人权限位直接授予：即时生效。
	if err := svc.Users().UserPermission("alice", "doc:write", true); err != nil {
		t.Fatalf("授予个人权限失败: %v", err)
	}
	if _, reason := svc.Authorize(token, "doc:write"); reason != ReasonOK {
		t.Fatalf("个人权限授予后应通过，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "个人权限位即时生效", "通过")
}

// TestRBACExistingTokenSurvivesTTL 证明权限模型实时化并不影响
// 此前签发、仍在有效期内的凭证继续可用。
func TestRBACExistingTokenSurvivesTTL(t *testing.T) {
	svc, clock := newRBACService(t)
	token, _, err := svc.Login("alice", "pw")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	clock.Advance(20 * time.Minute) // 绝对寿命内
	if _, reason := svc.Authorize(token, "doc:read"); reason != ReasonOK {
		t.Fatalf("有效期内既有令牌应继续可用，实际 %s", reason)
	}
	caseLog(t, businessRBAC, "有效期内既有凭证调整权限后仍可继续使用", "通过")
}

func TestRBACAuthorizerRealtime(t *testing.T) {
	users := NewUserStore()
	users.AddRole(Role{Name: "r", Permissions: map[string]bool{"p": true}})
	users.AddUser(User{Username: "bob", PasswordHash: HashPassword("x"), Roles: []string{"r"}})
	a := NewAuthorizer(users)
	if !a.Can("bob", "p") {
		t.Fatal("初始应有权限 p")
	}
	users.AddRole(Role{Name: "r", Permissions: map[string]bool{}})
	if a.Can("bob", "p") {
		t.Fatal("角色权限清空后应立即无权限")
	}
	caseLog(t, businessRBAC, "鉴权器实时读取角色定义", "通过")
}
