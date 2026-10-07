// Command demo 端到端演示本地会话认证与访问控制链路：
// 未登录、已登录无权限、触发节流三类请求在登录入口与权限入口下的结论。
package main

import (
	"fmt"
	"time"

	"github.com/feng111627/session-auth-guard-go/internal/auth"
	"github.com/feng111627/session-auth-guard-go/internal/guard"
)

func main() {
	clock := &auth.FixedClock{T: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}

	users := auth.NewUserStore()
	users.AddUser(&auth.User{ID: "u1", Username: "alice", PasswordHash: auth.HashPassword("correct-horse"), Roles: []string{"member"}})

	sessions := auth.NewSessionStore([]byte("demo-secret"), auth.DefaultSessionTTL, clock)
	rbac := auth.NewRBAC(func(name string) []string {
		roles, _ := users.SnapshotRoles(name)
		return roles
	})
	rbac.GrantRole("member", "doc:read") // member 只能读，不能写
	th := auth.NewThrottler(auth.DefaultThrottleConfig(), clock)
	svc := auth.NewService(users, sessions, rbac, th, clock)

	loginGate := guard.New(svc, "")          // 仅要求登录
	readGate := guard.New(svc, "doc:read")   // 要求读权限
	writeGate := guard.New(svc, "doc:write") // 要求写权限

	show := func(label, token string, e *guard.Entry) {
		d := e.Check(token)
		if d.Allowed {
			fmt.Printf("[%s] 允许访问\n", label)
		} else {
			fmt.Printf("[%s] 拒绝 reason=%s message=%s\n", label, d.Reason, d.Message)
		}
	}

	fmt.Println("== 1. 未登录访问两类入口 ==")
	show("未登录-登录入口", "", loginGate)
	show("未登录-写权限入口", "", writeGate)

	fmt.Println("\n== 2. 正常登录后访问 ==")
	token, err := svc.Login("alice", "correct-horse")
	if err != nil {
		panic(err)
	}
	show("已登录-登录入口", token, loginGate)
	show("已登录-读权限入口", token, readGate)
	show("已登录-写权限入口", token, writeGate) // forbidden

	fmt.Println("\n== 3. 权限提升即时生效（旧令牌不变） ==")
	users.SetRoles("alice", []string{"member", "admin"})
	rbac.GrantRole("admin", "doc:write")
	show("提权后-写权限入口", token, writeGate) // 允许
	users.SetRoles("alice", []string{"member"})
	show("降权后-写权限入口", token, writeGate) // 立即 forbidden

	fmt.Println("\n== 4. 续期与登出 ==")
	clock.Advance(20 * time.Minute)
	if _, rerr := svc.Renew(token); rerr != nil {
		panic(rerr)
	}
	fmt.Println("会话已续期 30 分钟，旧令牌继续可用")
	if rerr := svc.Logout(token); rerr != nil {
		panic(rerr)
	}
	show("登出后-读权限入口", token, readGate) // revoked

	fmt.Println("\n== 5. 登录节流（默认 5 次失败后锁定 5 分钟） ==")
	for i := 0; i < 5; i++ {
		if _, rerr := svc.Login("alice", "wrong"); rerr.Reason != auth.ReasonInvalidCredential {
			panic(fmt.Sprintf("第 %d 次失败结论异常: %v", i+1, rerr))
		}
	}
	if _, rerr := svc.Login("alice", "correct-horse"); rerr != nil {
		fmt.Printf("锁定期间即使密码正确也被拒绝: reason=%s until=%s\n", rerr.Reason, rerr.LockedUntil.Format(time.RFC3339))
	}
	clock.Advance(5 * time.Minute)
	if _, rerr := svc.Login("alice", "correct-horse"); rerr != nil {
		panic(rerr)
	}
	fmt.Println("锁定窗口结束，登录自动恢复")
}
