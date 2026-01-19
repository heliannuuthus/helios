package zwei

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/internal/auth"
	"github.com/heliannuuthus/helios/internal/logger"
)

// Service zwei 认证服务（小程序快捷授权）
type Service struct {
	authService *auth.Service
}

// NewService 创建 zwei 认证服务
func NewService(authService *auth.Service) *Service {
	return &Service{
		authService: authService,
	}
}

// Authorize 处理授权请求（小程序一步式登录）
// 这是简化流程：前端一次请求完成 authorize + login + token
func (s *Service) Authorize(ctx context.Context, req *AuthorizeRequest) (*TokenResponse, error) {
	logger.Infof("[Zwei] 开始授权流程 - ClientID: %s, Connection: %s", req.ClientID, req.Connection)

	// 验证 response_type
	if req.ResponseType != "code" {
		return nil, &OAuth2Error{
			ErrorCode:        "unsupported_response_type",
			ErrorDescription: fmt.Sprintf("不支持的 response_type: %s，仅支持 code", req.ResponseType),
		}
	}

	// 转换 connection 为 IDP
	var idp auth.IDP
	switch req.Connection {
	case "wechat:mp":
		idp = auth.IDPWechatMP
	case "tt:mp":
		idp = auth.IDPTTMP
	case "alipay:mp":
		idp = auth.IDPAlipayMP
	default:
		return nil, &OAuth2Error{
			ErrorCode:        "invalid_connection",
			ErrorDescription: fmt.Sprintf("不支持的 connection: %s，支持的连接: wechat:mp, tt:mp, alipay:mp", req.Connection),
		}
	}

	// 1. 创建授权会话
	authResp, err := s.authService.Authorize(ctx, &auth.AuthorizeRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: auth.CodeChallengeMethod(req.CodeChallengeMethod),
		State:               req.State,
		Scope:               req.Scope,
	})
	if err != nil {
		return nil, &OAuth2Error{
			ErrorCode:        "invalid_request",
			ErrorDescription: fmt.Sprintf("创建授权会话失败: %v", err),
		}
	}

	// 2. 登录
	loginResp, err := s.authService.Login(ctx, authResp.SessionID, &auth.LoginRequest{
		IDP:  idp,
		Code: req.Code,
	})
	if err != nil {
		return nil, &OAuth2Error{
			ErrorCode:        "invalid_grant",
			ErrorDescription: fmt.Sprintf("登录失败: %v", err),
		}
	}

	// 3. 换取 Token
	tokenResp, err := s.authService.ExchangeToken(ctx, &auth.TokenRequest{
		GrantType:    auth.GrantTypeAuthorizationCode,
		Code:         loginResp.Code,
		RedirectURI:  req.RedirectURI,
		ClientID:     req.ClientID,
		CodeVerifier: req.CodeVerifier,
	})
	if err != nil {
		return nil, &OAuth2Error{
			ErrorCode:        "invalid_grant",
			ErrorDescription: fmt.Sprintf("获取 Token 失败: %v", err),
		}
	}

	logger.Infof("[Zwei] 授权成功 - Connection: %s", req.Connection)

	// 构建响应（C 端用户使用 id_token）
	resp := &TokenResponse{
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        req.Scope,
		RefreshToken: tokenResp.RefreshToken,
	}

	if tokenResp.IDToken != "" {
		resp.AccessToken = tokenResp.IDToken // 小程序端统一用 access_token 字段返回
	} else {
		resp.AccessToken = tokenResp.AccessToken
	}

	return resp, nil
}
