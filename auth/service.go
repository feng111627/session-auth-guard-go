package auth

// ServiceConfig 聚合门面所需的全部配置。
type ServiceConfig struct {
	TokenSecret []byte
	Sessions    ManagerConfig
	Throttle    ThrottleConfig
}

// Principal 是认证成功后可被业务读取的身份信息。
type Principal struct {
	Username string
	Roles    []string
}

// Service 是登录、鉴权、续期、登出的统一门面（API 入口）。
// 它与 HTTP 入口共享同一套 Reason 结论，保证跨入口一致。
type Service struct {
	users      *UserStore
	sessions   *SessionManager
	authorizer *Authorizer
	throttler  *Throttler
	clock      Clock
}

// NewService 组装整套本地认证链路。
func NewService(cfg ServiceConfig) *Service {
	return NewServiceWithClock(cfg, NewRealClock())
}

// NewServiceWithClock 允许注入可控时钟（主要用于测试）。
func NewServiceWithClock(cfg ServiceConfig, clock Clock) *Service {
	users := NewUserStore()
	store := NewSessionStore()
	codec := NewTokenCodec(cfg.TokenSecret)
	return &Service{
		users:      users,
		sessions:   NewSessionManager(store, codec, clock, cfg.Sessions),
		authorizer: NewAuthorizer(users),
		throttler:  NewThrottler(clock, cfg.Throttle),
		clock:      clock,
	}
}

// Users 暴露用户存储以便配置用户与角色。
func (s *Service) Users() *UserStore { return s.users }

// Sessions 暴露会话管理器（管理/测试用途）。
func (s *Service) Sessions() *SessionManager { return s.sessions }

// Throttler 暴露节流器（测试用途）。
func (s *Service) Throttler() *Throttler { return s.throttler }

// Login 校验凭据并创建会话。关键安全语义：
//   - 先按身份维度做节流/锁定检查；
//   - 用户不存在与口令错误对外统一返回 ReasonInvalidCredentials，
//     两条路径都计入同一份失败计数，避免泄露账号是否存在；
//   - 成功后清零计数并签发新会话令牌。
func (s *Service) Login(username, password string) (string, Principal, error) {
	now := s.clock.Now()
	// 同一身份的“节流检查 -> 凭据验证 -> 结果登记”整体串行，
	// 保证并发失败计数精确、阈值只被跨越一次；不同身份互不阻塞。
	unlock := s.throttler.LockIdentity(username)
	defer unlock()

	if ok, reason := s.throttler.Check(username, now); !ok {
		return "", Principal{}, NewError(reason, "login temporarily rejected for "+username)
	}

	user, exists := s.users.GetUser(username)
	// 无论账号是否存在，都执行一次口令校验，使两条路径的工作量基本一致。
	credentialOK := exists && VerifyPassword(user.PasswordHash, password)
	if !exists {
		// 用一次恒定时间比较消耗相近时间，但不改变结论。
		_ = VerifyPassword(HashPassword("__no_such_user__"), password)
	}
	if !credentialOK {
		s.throttler.RecordFailure(username, now)
		return "", Principal{}, NewError(ReasonInvalidCredentials, "invalid username or password")
	}

	s.throttler.RecordSuccess(username)
	token, err := s.sessions.Create(username)
	if err != nil {
		return "", Principal{}, err
	}
	roles, _ := s.users.RolesOf(username)
	return token, Principal{Username: username, Roles: roles}, nil
}

// authenticateSession 内部共用：校验令牌并产出身份；错误映射为具体 Reason。
func (s *Service) authenticateSession(token string) (Principal, Session, Reason) {
	sess, err := s.sessions.Validate(token)
	if err != nil {
		if ae, ok := err.(*AuthError); ok {
			return Principal{}, Session{}, ae.Reason
		}
		return Principal{}, Session{}, ReasonMalformedToken
	}
	roles, _ := s.users.RolesOf(sess.Username)
	return Principal{Username: sess.Username, Roles: roles}, sess, ReasonOK
}

// Authenticate 仅认证，不做权限判定，返回身份与结论。
func (s *Service) Authenticate(token string) (Principal, Reason) {
	p, _, reason := s.authenticateSession(token)
	return p, reason
}

// Authorize 认证 + 权限判定：区分未认证与已认证但无权限。
// 权限实时读取 UserStore，角色/权限调整对存量会话立即生效，
// 而仍在有效期内的既有令牌依然可继续使用。
func (s *Service) Authorize(token, permission string) (Principal, Reason) {
	p, _, reason := s.authenticateSession(token)
	if reason != ReasonOK {
		return Principal{}, reason
	}
	if !s.authorizer.Can(p.Username, permission) {
		return p, ReasonPermissionDenied
	}
	return p, ReasonOK
}

// RenewSession 续期令牌，语义同 SessionManager.Renew。
func (s *Service) RenewSession(token string) (string, error) {
	newToken, _, err := s.sessions.Renew(token)
	return newToken, err
}

// Logout 主动失效会话；幂等，失效后该令牌及同会话旧令牌都不可再用。
func (s *Service) Logout(token string) error {
	return s.sessions.Revoke(token)
}
