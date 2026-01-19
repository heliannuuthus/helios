package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/logger"
	"gorm.io/gorm"
)

// Service 认证服务
type Service struct {
	db           *gorm.DB
	store        Store
	tokenManager *TokenManager
	idpManager   *IDPManager
}

// NewService 创建认证服务
func NewService(db *gorm.DB) (*Service, error) {
	tokenManager, err := NewTokenManager()
	if err != nil {
		return nil, fmt.Errorf("create token manager: %w", err)
	}

	return &Service{
		db:           db,
		store:        NewMemoryStore(), // TODO: 支持 Redis
		tokenManager: tokenManager,
		idpManager:   NewIDPManager(),
	}, nil
}

// ============= Authorize =============

// Authorize 创建认证会话
func (s *Service) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	// 1. 验证客户端
	client, err := s.getClient(req.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	// 2. 验证重定向 URI
	if !client.ValidateRedirectURI(req.RedirectURI) {
		return nil, NewError(ErrInvalidRequest, "invalid redirect_uri")
	}

	// 3. 创建会话
	sessionID := GenerateSessionID()
	session := &Session{
		ID:                  sessionID,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		State:               req.State,
		Scope:               req.Scope,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.store.SaveSession(ctx, session); err != nil {
		return nil, NewError(ErrServerError, "failed to create session")
	}

	logger.Infof("[Auth] 创建认证会话 - SessionID: %s, ClientID: %s", sessionID, req.ClientID)

	return &AuthorizeResponse{
		SessionID: sessionID,
	}, nil
}

// ============= Login =============

// Login 处理 IDP 登录
func (s *Service) Login(ctx context.Context, sessionID string, req *LoginRequest) (*LoginResponse, error) {
	// 1. 获取会话
	session, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			return nil, NewError(ErrInvalidRequest, "session not found or expired")
		}
		return nil, NewError(ErrServerError, err.Error())
	}

	// 2. 获取客户端并验证 IDP
	client, err := s.getClient(session.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	if !client.ValidateIDP(req.IDP) {
		return nil, NewError(ErrInvalidRequest, fmt.Sprintf("idp %s not allowed for this client", req.IDP))
	}

	// 3. 调用 IDP 换取用户信息
	idpResult, err := s.idpManager.Exchange(ctx, req.IDP, req.Code)
	if err != nil {
		logger.Errorf("[Auth] IDP 认证失败 - IDP: %s, Error: %v", req.IDP, err)
		return nil, NewError(ErrAccessDenied, fmt.Sprintf("idp auth failed: %v", err))
	}

	// 4. 查找或创建用户
	user, err := s.findOrCreateUser(ctx, req.IDP, idpResult)
	if err != nil {
		return nil, NewError(ErrServerError, fmt.Sprintf("user management failed: %v", err))
	}

	// 5. 更新会话
	session.UserID = user.ID
	session.IDP = req.IDP
	if err := s.store.UpdateSession(ctx, session); err != nil {
		return nil, NewError(ErrServerError, "failed to update session")
	}

	// 6. 生成授权码
	code := GenerateAuthorizationCode()
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            session.ClientID,
		RedirectURI:         session.RedirectURI,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: string(session.CodeChallengeMethod),
		Scope:               session.Scope,
		UserID:              user.ID,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	if err := s.store.SaveAuthCode(ctx, authCode); err != nil {
		return nil, NewError(ErrServerError, "failed to save authorization code")
	}

	// 7. 删除会话
	_ = s.store.DeleteSession(ctx, sessionID)

	// 8. 构建响应
	redirectURI := session.RedirectURI + "?code=" + url.QueryEscape(code)
	if session.State != "" {
		redirectURI += "&state=" + url.QueryEscape(session.State)
	}

	logger.Infof("[Auth] 登录成功 - UserID: %s, IDP: %s", user.ID, req.IDP)

	return &LoginResponse{
		Code:        code,
		RedirectURI: redirectURI,
	}, nil
}

// ============= Token =============

// ExchangeToken 交换 Token
func (s *Service) ExchangeToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return s.exchangeRefreshToken(ctx, req)
	default:
		return nil, NewError(ErrUnsupportedGrantType, "unsupported grant type")
	}
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 获取授权码
	authCode, err := s.store.GetAuthCode(ctx, req.Code)
	if err != nil {
		return nil, NewError(ErrInvalidGrant, "invalid or expired authorization code")
	}

	// 2. 验证客户端
	if req.ClientID != authCode.ClientID {
		return nil, NewError(ErrInvalidGrant, "client_id mismatch")
	}

	// 3. 验证重定向 URI
	if req.RedirectURI != authCode.RedirectURI {
		return nil, NewError(ErrInvalidGrant, "redirect_uri mismatch")
	}

	// 4. 验证 PKCE
	if !VerifyCodeChallenge(CodeChallengeMethod(authCode.CodeChallengeMethod), authCode.CodeChallenge, req.CodeVerifier) {
		return nil, NewError(ErrInvalidGrant, "invalid code_verifier")
	}

	// 5. 标记授权码已使用
	if err := s.store.MarkAuthCodeUsed(ctx, req.Code); err != nil {
		return nil, NewError(ErrServerError, "failed to mark code as used")
	}

	// 6. 获取用户和客户端
	user, err := s.getUserByID(authCode.UserID)
	if err != nil {
		return nil, NewError(ErrServerError, "user not found")
	}

	client, err := s.getClient(authCode.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	// 7. 生成 Token
	return s.generateTokens(ctx, client, user, authCode.Scope)
}

func (s *Service) exchangeRefreshToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 获取 Refresh Token
	var refreshToken RefreshToken
	if err := s.db.Where("token = ? AND revoked = ?", req.RefreshToken, false).First(&refreshToken).Error; err != nil {
		return nil, NewError(ErrInvalidGrant, "invalid refresh token")
	}

	// 2. 检查是否有效
	if !refreshToken.IsValid() {
		return nil, NewError(ErrInvalidGrant, "refresh token expired or revoked")
	}

	// 3. 验证客户端
	if req.ClientID != refreshToken.ClientID {
		return nil, NewError(ErrInvalidGrant, "client_id mismatch")
	}

	// 4. 获取用户和客户端
	user, err := s.getUserByID(refreshToken.UserID)
	if err != nil {
		return nil, NewError(ErrServerError, "user not found")
	}

	client, err := s.getClient(refreshToken.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	// 5. 生成新的 Access Token（不轮转 Refresh Token）
	accessTTL := time.Duration(client.AccessTokenExpiresIn) * time.Second
	if accessTTL == 0 {
		accessTTL = time.Duration(config.GetInt("auth.expires-in")) * time.Second
	}

	var token string
	if user.Domain == DomainCIAM {
		token, err = s.tokenManager.CreateIDToken(user.ID, client.ID, user.Domain, user.Name, user.Picture, accessTTL)
	} else {
		token, err = s.tokenManager.CreateAccessToken(user.ID, client.ID, user.Domain, accessTTL)
	}
	if err != nil {
		return nil, NewError(ErrServerError, "failed to create token")
	}

	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
		RefreshToken: refreshToken.Token,
	}

	if user.Domain == DomainCIAM {
		resp.IDToken = token
	} else {
		resp.AccessToken = token
	}

	return resp, nil
}

// ============= Revoke =============

// RevokeToken 撤销 Token
func (s *Service) RevokeToken(ctx context.Context, token string) error {
	result := s.db.Model(&RefreshToken{}).Where("token = ?", token).Update("revoked", true)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// RevokeAllTokens 撤销用户所有 Token
func (s *Service) RevokeAllTokens(userID string) int64 {
	result := s.db.Model(&RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true)
	return result.RowsAffected
}

// ============= UserInfo =============

// GetUserInfo 获取用户信息
func (s *Service) GetUserInfo(userID string) (*UserInfoResponse, error) {
	user, err := s.getUserByID(userID)
	if err != nil {
		return nil, err
	}

	// TODO: 解密手机号
	phone := ""

	return user.ToUserInfo(phone), nil
}

// UpdateUserInfo 更新用户信息
func (s *Service) UpdateUserInfo(userID string, req *UpdateUserInfoRequest) (*UserInfoResponse, error) {
	user, err := s.getUserByID(userID)
	if err != nil {
		return nil, err
	}

	updates := make(map[string]any)
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Picture != "" {
		updates["picture"] = req.Picture
	}

	if len(updates) > 0 {
		if err := s.db.Model(user).Updates(updates).Error; err != nil {
			return nil, err
		}
	}

	return s.GetUserInfo(userID)
}

// ============= Helper Methods =============

func (s *Service) getClient(clientID string) (*Client, error) {
	var client Client
	if err := s.db.Preload("RedirectURIs").Preload("AllowedIDPs").
		Where("id = ?", clientID).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *Service) getUserByID(userID string) (*User, error) {
	var user User
	if err := s.db.Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) findOrCreateUser(ctx context.Context, idp IDP, result *IDPResult) (*User, error) {
	domain := idp.GetDomain()

	// 1. 查找已有身份
	var identity UserIdentity
	err := s.db.Where("idp = ? AND provider_id = ?", idp, result.ProviderID).First(&identity).Error

	if err == nil {
		// 找到身份，获取用户
		var user User
		if err := s.db.Where("id = ?", identity.UserID).First(&user).Error; err != nil {
			return nil, err
		}
		s.db.Model(&user).Update("last_login_at", time.Now())
		logger.Infof("[Auth] 找到已有用户 - UserID: %s, IDP: %s", user.ID, idp)
		return &user, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 2. 检查是否支持自动创建
	if !idp.SupportsAutoCreate() {
		return nil, errors.New("user not found and auto-create not supported for this idp")
	}

	// 3. 创建新用户
	now := time.Now()
	user := User{
		ID:          GenerateUserID(),
		Domain:      domain,
		Name:        generateRandomName(),
		Picture:     generateRandomAvatar(result.ProviderID),
		LastLoginAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}

		identity := UserIdentity{
			UserID:     user.ID,
			IDP:        idp,
			ProviderID: result.ProviderID,
			UnionID:    result.UnionID,
			RawData:    result.RawData,
			CreatedAt:  now,
			UpdatedAt:  now,
		}

		return tx.Create(&identity).Error
	})

	if err != nil {
		return nil, err
	}

	logger.Infof("[Auth] 创建新用户 - UserID: %s, IDP: %s", user.ID, idp)
	return &user, nil
}

func (s *Service) generateTokens(ctx context.Context, client *Client, user *User, scope string) (*TokenResponse, error) {
	now := time.Now()

	accessTTL := time.Duration(client.AccessTokenExpiresIn) * time.Second
	if accessTTL == 0 {
		accessTTL = time.Duration(config.GetInt("auth.expires-in")) * time.Second
	}

	refreshTTL := time.Duration(client.RefreshTokenExpiresIn) * time.Second
	if refreshTTL == 0 {
		refreshTTL = time.Duration(config.GetInt("auth.refresh-expires-in")) * 24 * time.Hour
	}

	resp := &TokenResponse{
		TokenType: "Bearer",
		ExpiresIn: int(accessTTL.Seconds()),
	}

	var err error
	if user.Domain == DomainCIAM {
		// C 端用户使用 ID Token
		resp.IDToken, err = s.tokenManager.CreateIDToken(user.ID, client.ID, user.Domain, user.Name, user.Picture, accessTTL)
	} else {
		// B 端用户使用 Access Token
		resp.AccessToken, err = s.tokenManager.CreateAccessToken(user.ID, client.ID, user.Domain, accessTTL)
	}
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	// 创建 Refresh Token
	s.cleanupOldRefreshTokens(user.ID, client.ID)

	refreshToken := &RefreshToken{
		Token:     GenerateRefreshTokenValue(),
		UserID:    user.ID,
		ClientID:  client.ID,
		Scope:     scope,
		ExpiresAt: now.Add(refreshTTL),
		CreatedAt: now,
	}

	if err := s.db.Create(refreshToken).Error; err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	resp.RefreshToken = refreshToken.Token

	return resp, nil
}

func (s *Service) cleanupOldRefreshTokens(userID, clientID string) {
	maxTokens := config.GetInt("auth.max-refresh-token")
	if maxTokens <= 0 {
		maxTokens = 10
	}

	var tokens []RefreshToken
	s.db.Where("user_id = ? AND client_id = ? AND revoked = ?", userID, clientID, false).
		Order("created_at DESC").
		Find(&tokens)

	if len(tokens) >= maxTokens {
		for _, t := range tokens[maxTokens-1:] {
			s.db.Model(&t).Update("revoked", true)
		}
	}
}

func generateRandomName() string {
	adjectives := []string{"快乐的", "聪明的", "勇敢的", "温柔的", "活泼的", "安静的", "优雅的", "幽默的"}
	nouns := []string{"小猫", "小狗", "小鸟", "小鱼", "小兔", "小熊", "小鹿", "小羊"}

	adjIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	nounIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))

	return adjectives[adjIndex.Int64()] + nouns[nounIndex.Int64()] + fmt.Sprintf("%04d", time.Now().Unix()%10000)
}

func generateRandomAvatar(seed string) string {
	hash := 0
	for _, c := range seed {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return fmt.Sprintf("https://api.dicebear.com/7.x/avataaars/svg?seed=%s&size=200", fmt.Sprintf("user%d", hash%10))
}
