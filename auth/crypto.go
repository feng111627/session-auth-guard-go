package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// passwordSalt 是本地演示用的固定应用盐。真实部署应改为每用户随机盐
// 并使用慢哈希（如 bcrypt/argon2）；此处以内存模拟为主，不引入外部依赖。
const passwordSalt = "session-auth-guard/local-v1:"

// HashPassword 返回口令在本地演示方案下的哈希表示。
func HashPassword(password string) string {
	sum := sha256.Sum256([]byte(passwordSalt + password))
	return hex.EncodeToString(sum[:])
}

// VerifyPassword 以恒定时间比较口令哈希，避免时序差异直接区分比较结果。
func VerifyPassword(hash, password string) bool {
	got := HashPassword(password)
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1
}
