package token

import (
	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/token"
)

// 类型别名（便于 internal 包使用）
type (
	UserInfo           = pkgtoken.UserInfo
	Token              = pkgtoken.Token
	TokenType          = pkgtoken.TokenType
	ChallengeType      = pkgtoken.ChallengeType
	UserAccessToken    = pkgtoken.UserAccessToken
	ServiceAccessToken = pkgtoken.ServiceAccessToken
	ChallengeToken     = pkgtoken.ChallengeToken
	ClientAccessToken  = pkgtoken.ClientAccessToken
)

// 常量别名
const (
	TokenTypeCAT       = pkgtoken.TokenTypeCAT
	TokenTypeUAT       = pkgtoken.TokenTypeUAT
	TokenTypeSAT       = pkgtoken.TokenTypeSAT
	TokenTypeChallenge = pkgtoken.TokenTypeChallenge
)

// 构造函数别名
var (
	NewUserAccessToken    = pkgtoken.NewUserAccessToken
	NewServiceAccessToken = pkgtoken.NewServiceAccessToken
	NewChallengeToken     = pkgtoken.NewChallengeToken
	UserInfoFromScope     = pkgtoken.UserInfoFromScope
	Build                 = pkgtoken.Build
	AsUAT                 = pkgtoken.AsUAT
	AsCAT                 = pkgtoken.AsCAT
	AsSAT                 = pkgtoken.AsSAT
	AsChallenge           = pkgtoken.AsChallenge
)
