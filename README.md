# session-auth-guard-go

一套纯内存实现的本地会话认证与访问控制链路（Go）。它把「未登录 / 已登录但无权限 /
触发节流锁定」等情形统一翻译为**可区分、可解释的结论（Reason）**，并在服务 API 入口
与 HTTP 中间件入口上保持完全一致。无外部依赖，仅用标准库。

## 能力总览

| 业务 | 关键结论 Reason | 说明 |
| --- | --- | --- |
| 会话/令牌生命周期 | `no_credentials` / `malformed_token` / `bad_signature` / `session_not_found` / `session_expired` / `session_revoked` / `duplicate_renewal` | 创建、校验、续期、主动失效；失效原因逐项可区分 |
| 基于角色的访问控制 | `permission_denied` 与未认证结论区分 | 权限实时判定，角色/权限调整对存量会话即时生效 |
| 登录节流与锁定 | `invalid_credentials` / `locked` / `throttled` | 按身份维度计数，达阈值锁定，窗口结束自动恢复 |

## 包内文件

- `clock.go`：时间抽象（真实时钟 + 测试用可控假时钟）。
- `reason.go`：统一结论枚举、错误类型与 HTTP 状态码映射。
- `user.go`：内存用户/角色存储，实时 RBAC 数据来源（读写锁保护）。
- `session.go`：会话权威记录与内存存储，含 CAS 续期/失效原语。
- `token.go`：HMAC-SHA256 令牌签发与校验（`base64(payload).base64(hmac)`）。
- `manager.go`：会话创建、校验、续期、失效的生命周期编排。
- `authorizer.go`：实时权限判定（不缓存「会话→权限」快照）。
- `throttle.go`：按身份维度的失败计数、固定窗口与锁定（含身份串行锁）。
- `crypto.go`：本地演示用口令哈希与恒定时间比较。
- `service.go`：统一门面（API 入口）：`Login / Authenticate / Authorize / RenewSession / Logout`。
- `http.go`：HTTP 中间件入口，解析 `Authorization: Bearer <token>` 并输出同一套结论。

## 会话与令牌：过期与失效语义

- 服务端保存会话**权威记录** `Session`；令牌只是对它的**签名引用**，载荷含
  `session_id / username / generation / expires_at`，以 HMAC-SHA256 防篡改。
- 判定时一律**以服务端记录为准**，令牌内的过期时间仅为冗余信息。
- **双重过期**：
  - 绝对寿命 `AbsoluteTTL`：自创建起到点必过期。
  - 空闲寿命 `IdleTTL`：距上次成功活动超时即过期；每次成功校验会把空闲截止时间向后滑动。
- **主动失效（撤销）**：`Logout/Revoke` 会把会话置为 `revoked`。失效后该令牌以及指向
  同一会话的任何旧令牌都不可再用；重复失效幂等。
- **续期与并发**：会话带单调递增的 `Generation`（创建为 1，每次成功续期 +1）。
  续期用「比较并交换（CAS）」完成：仅当令牌携带的代际等于当前代际时才推进一代。
  因此同一会话的同一代令牌，即使在同一时刻被大量 goroutine 并发续期，也**恰好一次成功**，
  其余返回 `duplicate_renewal`；新代令牌可继续续期。
- 拒绝原因严格区分：无凭证、格式非法、签名不符、会话不存在、已过期、已撤销、重复续期。

> 为什么用代际而不是续期时间戳？高并发下多个续期可能落在同一时间单位内，时间戳无法
> 区分先后；单调代际可以确定性地保证「只续一次」。

## 权限模型

- 用户（`User`）持有若干角色（`Role`），另可挂个人权限位；最终权限为
  「各角色权限」∪「个人权限」。
- 鉴权**不缓存**会话与权限的关系：每次 `Authorize` 都实时读取 `UserStore`。
  因此授予/摘除角色、修改角色权限、增删个人权限，对**已建立的会话立即生效**，
  不会因缓存或旧状态造成越权。
- 与此同时，此前签发、仍在有效期内的令牌依旧可用——令牌只证明「你是谁」，
  「你能做什么」每次实时计算。
- 未认证与已认证无权限严格区分：前者为 401（`no_credentials` 等），
  后者为 403（`permission_denied`）。

## 节流与锁定规则

- 维度：身份（用户名）。**不存在的用户名同样独立计数**，且对外结论与口令错误完全一致
  （`invalid_credentials`，同一文案），两条路径都执行口令比较，避免暴露账号是否存在。
- 计数：固定窗口 `Window`，从窗口内第一次失败起计时；并发失败计数精确（见下）。
- 阈值与恢复（`MaxFailures`、`LockDuration`、`Window`）：
  - 窗口内失败数达到 `MaxFailures` 后进入硬锁定；
  - 硬锁定期内即使口令正确也拒绝，结论为 `locked`（HTTP 429）；
  - 硬锁定结束但计数窗口未结束期间拒绝，结论为 `throttled`（HTTP 429）；
  - 计数窗口结束后失败数与锁定全部清零，**自动恢复**可登录；
  - 登录成功立即清零该身份计数。
- 并发准确性：`Login` 对同一身份的「节流检查 → 凭据验证 → 结果登记」整体串行
  （每身份一把锁，不同身份仍并行），消除 check/record 之间的竞态，阈值只被跨越一次。

## 快速使用

```go
svc := auth.NewService(auth.ServiceConfig{
    TokenSecret: []byte("dev-secret"),
    Sessions:    auth.ManagerConfig{AbsoluteTTL: 2 * time.Hour, IdleTTL: 30 * time.Minute},
    Throttle:    auth.ThrottleConfig{MaxFailures: 5, Window: time.Minute, LockDuration: 30 * time.Second},
})

svc.Users().AddRole(auth.Role{Name: "viewer", Permissions: map[string]bool{"doc:read": true}})
svc.Users().AddUser(auth.User{Username: "alice", PasswordHash: auth.HashPassword("pw"), Roles: []string{"viewer"}})

token, _, err := svc.Login("alice", "pw")
_, reason := svc.Authorize(token, "doc:read") // auth.ReasonOK

// HTTP 入口（与 API 入口同一套结论与状态码）
handler := auth.NewMiddleware(svc, "doc:read").Wrap(myHandler)
```

## 本地验证方法

```bash
# 构建与静态检查
go build ./...
go vet ./...

# 全量单测（含竞态检测）
go test ./... -race -count=1

# 查看每个业务与其用例、结论的覆盖日志
go test ./... -race -count=1 -v
```

测试覆盖的关键场景：

- 并发续期：64 个 goroutine 用同一代令牌续期，恰好 1 次成功、63 次 `duplicate_renewal`。
- 失效后重用：撤销后原令牌（及同会话旧令牌）立即不可用，重复撤销幂等。
- 权限变更即时生效：提权 / 角色收权 / 摘除角色 / 个人权限，均在不重登的情况下对存量会话生效。
- 锁定与恢复：达阈值 `locked` → 硬锁结束 `throttled` → 窗口结束自动恢复可登录。
- 并发失败精确计数：20 个并发错误登录恰为 5 次 `invalid_credentials` + 15 次 `locked`。
- 跨入口一致：HTTP 中间件对未登录 / 篡改 / 无权限 / 有权 / 登出后的状态码与原因与服务 API 一致。

## 安全说明（演示边界）

`crypto.go` 使用固定应用盐 + SHA-256 仅为本地内存演示，避免引入外部依赖。
生产环境应改为每用户随机盐并使用慢哈希（bcrypt/argon2），并妥善管理 HMAC 密钥。
