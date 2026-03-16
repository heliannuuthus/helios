package token

import (
	pkgtoken "github.com/heliannuuthus/aegis-go/utilities/token"
)

// 类型别名（便于 internal 包使用）
type (
	Token              = pkgtoken.Token
	TokenType          = pkgtoken.TokenType
	UserAccessToken    = pkgtoken.UserAccessToken
	ServiceAccessToken = pkgtoken.ServiceAccessToken
	ChallengeToken     = pkgtoken.ChallengeToken
	ClientToken        = pkgtoken.ClientToken
	// Builder 类型别名
	ClaimsBuilder    = pkgtoken.ClaimsBuilder
	TokenTypeBuilder = pkgtoken.TokenTypeBuilder
	// TokenType Builder 别名
	UAT = pkgtoken.UAT
	SAT = pkgtoken.SAT
	CT  = pkgtoken.CT
	XT  = pkgtoken.XT
)

// 常量别名
const (
	TokenTypeCT        = pkgtoken.TokenTypeCT
	TokenTypeUAT       = pkgtoken.TokenTypeUAT
	TokenTypeSAT       = pkgtoken.TokenTypeSAT
	TokenTypeChallenge = pkgtoken.TokenTypeChallenge
	TokenTypeSSO       = pkgtoken.TokenTypeSSO
)

// 构造函数别名
var (
	Build = pkgtoken.Build
	// Builder 构造函数
	NewClaimsBuilder             = pkgtoken.NewClaimsBuilder
	NewUserAccessTokenBuilder    = pkgtoken.NewUserAccessTokenBuilder
	NewServiceAccessTokenBuilder = pkgtoken.NewServiceAccessTokenBuilder
	NewClientTokenBuilder        = pkgtoken.NewClientTokenBuilder
	NewChallengeTokenBuilder     = pkgtoken.NewChallengeTokenBuilder
)
