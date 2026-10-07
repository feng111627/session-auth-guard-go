# session-auth-guard-go

本地会话认证与访问控制链路的内存实现。用户、会话、失败计数全部存放在内存中，
不依赖外部服务；重点是把 **未登录、已登录无权限、触发节流** 三类请求在不同入口下
处理成一致且可解释的结论，并严格处理凭证生命周期与并发。

## 包结构

| 路径 | 职责 |
| --- | --- |
| `internal/auth/clock.go` | 时钟抽象（`RealClock` / `FixedClock`），测试可精确驱动过期与窗口恢复 |
| `internal/auth/errors.go` | 结构化拒绝原因 `RejectReason` 与 `RejectError` |
| `internal/auth/user.go` | 用户与角色的内存存储，角色调整即时可见 |
| `internal/auth/session.go` | 会话记录、HMAC 不透明令牌、校验/续期/失效（singleflight 并发去重） |
| `internal/auth/rbac.go` | 角色→权限映射，鉴权时实时解析用户角色，不缓存用户状态 |
| `internal/auth/throttle.go` | 按身份维度的失败计数、计数窗口与锁定 |
| `internal/auth/service.go` | 组合门面：`Login / Authenticate / Authorize / Renew / Logout` |
| `internal/guard/guard.go` | 访问入口：统一 `Decision` 结论与 HTTP 中间件状态码映射 |
| `cmd/demo` | 端到端可运行演示 |

## 会话与令牌的过期 / 失效语义

- 令牌是**不透明**的：`<base64url 会话ID>.<base64url HMAC-SHA256(会话ID)>`。
  它本身不携带状态，一切结论以服务端会话记录为准。
- 默认会话有效期 `DefaultSessionTTL = 30m`。校验顺序为：

  1. 令牌结构非法或 HMAC 对不上 → `malformed_token`（被篡改 / 伪造）
  2. 签名合法但服务端无此会话 → `unknown_session`
  3. 会话已被登出 / 管理员失效 → `revoked_session`
  4. 当前时间 ≥ 到期时间 → `expired_session`
  5. 其余 → 放行

- **续期**：`Renew` 把到期时间重设为 `now + ttl`，令牌字符串不变，旧凭证继续可用。
  同一会话的并发续期通过 singleflight 合并为一次实际续期（`Version` 只自增一次，
  有效期不会重复叠加）；已失效或已过期的会话不能续期。续期与失效共用同一把互斥锁，
  失效一旦完成并返回，后续任何 `Validate/Renew` 都必然得到 `revoked_session`。
- **失效**：`Revoke`/`Logout` 幂等，重复调用不报错。

## 权限模型（RBAC）

- 用户持有若干**角色**，角色持有若干**权限**字符串（如 `doc:read`、`doc:write`）。
- `Authorize` 每次都通过 resolver **实时**读取用户当前角色，再与角色权限映射比对：
  会话里不缓存角色，因此 `GrantRole / RevokePermission / SetRoles` 对所有既有会话
  **立即生效**，不会因旧状态越权；令牌在有效期内仍可继续使用。
- 两类未放行结论严格区分：

  - 凭证缺失或无效 → 401，原因是 `unauthenticated` / `malformed_token` /
    `unknown_session` / `revoked_session` / `expired_session`
  - 已认证但缺权限 → 403，原因 `forbidden`

- 权限检查先认证后授权，所以凭证有问题时永远返回凭证类原因，不会误报 `forbidden`。

## 登录节流与锁定

- 计数维度是**登录身份（用户名）**，各身份互不影响。
- 默认策略 `DefaultThrottleConfig`：连续失败 `5` 次 → 锁定 `5m`；计数窗口 `10m`。
- 规则细节：
  - **账号枚举防护**：账号不存在与密码错误返回完全相同的错误
    （`invalid_credential`，同一文案），两类失败同样计入节流；无论用户是否存在
    都会执行一次口令摘要计算，减少耗时侧信道。
  - 锁定期间即使密码正确也返回 `too_many_attempts`（HTTP 429），并带锁定截止时间。
  - 锁定期满后**自动恢复**、计数清零；计数窗口外的旧失败自动作废。
  - 锁定期内继续失败不会延长锁定期，避免被无限锁定；成功登录立即清空计数。
  - 所有计数更新在互斥锁内完成，并发失败计数准确。

## HTTP 入口

`guard.New(svc, 权限)` 构造入口：权限传空串表示仅要求登录。中间件从
`Authorization: Bearer <token>` 取令牌，拒绝时返回 JSON：

```json
{ "allowed": false, "reason": "forbidden", "message": "missing required permission: doc:write" }
```

状态码映射：`forbidden → 403`，`too_many_attempts → 429`，其余拒绝原因 → `401`。

## 本地验证

要求 Go 1.25+。

```bash
# 全量测试（建议带竞态检测）
go test ./... -race -v

# 仅跑某条业务链路
go test ./internal/auth/ -run TestConcurrentRenewNoDuplicate -race -v

# 端到端演示：未登录 / 无权限 / 权限即时生效 / 续期登出 / 锁定恢复
go run ./cmd/demo
```

测试日志按“业务 → 用例”打印，例如：

```
业务[并发续期] 用例[64 个并发请求只续期一次] 通过：Version=1，到期=...
业务[权限即时生效] 用例[降权不失效凭证] 通过：doc:write 被拒，但令牌认证仍通过
业务[节流锁定] 用例[到期自动恢复] 通过：锁定解除，计数清零
```

### 已覆盖的关键场景

- 会话创建、校验、过期拒绝、主动失效、重复失效幂等、失效后重用拒绝
- 令牌结构篡改、签名篡改、合法签名但会话未知
- 64 路并发续期只生效一次；续期与失效 32+32 并发竞态后状态确定为已失效
- 角色授予 / 回收 / 用户换角色对旧令牌即时生效，降权不使凭证失效
- 未登录 401 与已登录无权限 403 可区分；凭证问题优先于权限问题
- 达到阈值锁定、锁定期正确密码被拒、锁定期满自动恢复、计数窗口过期、身份维度隔离
- 50 路并发失败计数准确
