package token

import (
	"errors"

	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/token"
)

// Token 验证错误
var (
	ErrUnsupportedAudience = errors.New("unsupported audience")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrMissingClaims       = errors.New("missing required claims")
)

// Claims 类型别名（使用 pkg/aegis/token 中的定义）
type Claims = pkgtoken.Claims

// UserInfo 类型别名（使用 pkg/aegis/token 中的定义）
type UserInfo = pkgtoken.UserInfo

// VerifiedToken 类型别名（使用 pkg/aegis/token 中的定义）
type VerifiedToken = pkgtoken.VerifiedToken

// AccessToken 类型别名（使用 pkg/aegis/token 中的定义）
type AccessToken = pkgtoken.AccessToken
