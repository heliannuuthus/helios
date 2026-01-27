package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// CodeChallengeMethod PKCE 验证方法（OAuth2.1 只允许 S256）
type CodeChallengeMethod string

const (
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

// GenerateAuthorizationCode 生成授权码
func GenerateAuthorizationCode() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// GenerateSessionID 生成会话 ID
func GenerateSessionID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// VerifyCodeChallenge 验证 PKCE（只支持 S256）
func VerifyCodeChallenge(method CodeChallengeMethod, challenge, verifier string) bool {
	if method != CodeChallengeMethodS256 {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return computed == challenge
}

// 内部辅助函数（避免重复导入）
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

func hexEncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}
