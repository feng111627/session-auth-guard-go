package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// TokenClaims 是令牌中签名保护的内容。
type TokenClaims struct {
	SessionID string `json:"sid"`
	Username  string `json:"usr"`
	// Generation 与签发时会话的代际一致，用于识别过期版本的续期请求。
	Generation int64 `json:"gen"`
	// ExpiresAt 冗余绝对过期时刻，解码后仍以服务端记录为准。
	ExpiresAt time.Time `json:"exp"`
}

// TokenCodec 负责令牌的签发与校验，使用 HMAC-SHA256 防止篡改。
// 令牌形态： base64url(payloadJSON).base64url(hmac(payload))
type TokenCodec struct {
	secret []byte
}

// NewTokenCodec 用给定密钥构造编解码器。
func NewTokenCodec(secret []byte) *TokenCodec {
	return &TokenCodec{secret: secret}
}

func (c *TokenCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write(payload)
	return mac.Sum(nil)
}

// Issue 为 claims 生成不透明令牌字符串。
func (c *TokenCodec) Issue(claims TokenClaims) string {
	raw, err := json.Marshal(claims)
	if err != nil {
		// TokenClaims 全部为可序列化类型，此处理论上不会发生。
		return ""
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	sig := base64.RawURLEncoding.EncodeToString(c.sign([]byte(payload)))
	return payload + "." + sig
}

// Parse 校验格式与签名并还原 claims。
// 格式非法返回 ReasonMalformedToken，签名不符返回 ReasonBadSignature。
func (c *TokenCodec) Parse(token string) (TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return TokenClaims{}, NewError(ReasonMalformedToken, "token must be payload.signature")
	}
	payload := parts[0]
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return TokenClaims{}, NewError(ReasonMalformedToken, "signature is not valid base64")
	}
	expected := c.sign([]byte(payload))
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return TokenClaims{}, NewError(ReasonBadSignature, "token signature mismatch")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return TokenClaims{}, NewError(ReasonMalformedToken, "payload is not valid base64")
	}
	var claims TokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return TokenClaims{}, NewError(ReasonMalformedToken, "payload is not valid json")
	}
	if claims.SessionID == "" {
		return TokenClaims{}, NewError(ReasonMalformedToken, "missing session id")
	}
	return claims, nil
}
