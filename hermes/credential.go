package hermes

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/hermes/models"
	cryptoutil "github.com/heliannuuthus/helios/pkg/crypto"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// CredentialService 凭证服务
type CredentialService struct {
	db *gorm.DB
}

// NewCredentialService 创建凭证服务
func NewCredentialService(db *gorm.DB) *CredentialService {
	return &CredentialService{db: db}
}

// ==================== TOTP 相关 ====================

// TOTPSetupRequest TOTP 设置请求
type TOTPSetupRequest struct {
	OpenID  string // 用户标识
	AppName string // 应用名称（显示在 Authenticator App 中）
}

// TOTPSetupResponse TOTP 设置响应
type TOTPSetupResponse struct {
	Secret       string `json:"secret"`        // Base32 编码的密钥（用于手动输入）
	OTPAuthURI   string `json:"otpauth_uri"`   // OTPAuth URI（用于二维码扫描）
	CredentialID uint   `json:"credential_id"` // 凭证 ID（用于后续确认）
}

// SetupTOTP 初始化 TOTP（生成密钥，但尚未启用）
func (s *CredentialService) SetupTOTP(ctx context.Context, req *TOTPSetupRequest) (*TOTPSetupResponse, error) {
	// 检查用户是否已有启用的 TOTP
	var existing models.UserCredential
	err := s.db.WithContext(ctx).
		Where("openid = ? AND type = ? AND enabled = ?", req.OpenID, models.CredentialTypeTOTP, true).
		First(&existing).Error
	if err == nil {
		return nil, errors.New("用户已绑定 TOTP")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("查询 TOTP 失败: %w", err)
	}

	// 生成 TOTP 密钥（20 字节 = 160 bits）
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("生成密钥失败: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	// 构建 OTPAuth URI
	issuer := req.AppName
	if issuer == "" {
		issuer = "Helios"
	}
	account := req.OpenID

	otpauthURI := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer),
		url.PathEscape(account),
		secret,
		url.QueryEscape(issuer),
	)

	// 加密存储密钥
	secretData := &models.TOTPSecret{Secret: secret}
	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		return nil, fmt.Errorf("序列化密钥失败: %w", err)
	}

	encKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return nil, fmt.Errorf("获取加密密钥失败: %w", err)
	}

	encryptedSecret, err := cryptoutil.Encrypt(encKey, string(secretJSON), req.OpenID)
	if err != nil {
		return nil, fmt.Errorf("加密密钥失败: %w", err)
	}

	// 保存凭证（enabled = false，等待验证确认）
	credential := &models.UserCredential{
		OpenID:  req.OpenID,
		Type:    string(models.CredentialTypeTOTP),
		Enabled: false,
		Secret:  encryptedSecret,
	}

	if err := s.db.WithContext(ctx).Create(credential).Error; err != nil {
		return nil, fmt.Errorf("保存凭证失败: %w", err)
	}

	return &TOTPSetupResponse{
		Secret:       secret,
		OTPAuthURI:   otpauthURI,
		CredentialID: credential.ID,
	}, nil
}

// ConfirmTOTPRequest TOTP 确认请求
type ConfirmTOTPRequest struct {
	OpenID       string // 用户标识
	CredentialID uint   // 凭证 ID
	Code         string // 验证码
}

// ConfirmTOTP 确认 TOTP 绑定（验证一次后启用）
func (s *CredentialService) ConfirmTOTP(ctx context.Context, req *ConfirmTOTPRequest) error {
	// 获取凭证
	var credential models.UserCredential
	err := s.db.WithContext(ctx).
		Where("_id = ? AND openid = ? AND type = ? AND enabled = ?", req.CredentialID, req.OpenID, models.CredentialTypeTOTP, false).
		First(&credential).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("凭证不存在或已启用")
		}
		return fmt.Errorf("查询凭证失败: %w", err)
	}

	// 解密密钥
	encKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return fmt.Errorf("获取加密密钥失败: %w", err)
	}

	secretJSON, err := cryptoutil.Decrypt(encKey, credential.Secret, req.OpenID)
	if err != nil {
		return fmt.Errorf("解密密钥失败: %w", err)
	}

	var secretData models.TOTPSecret
	if err := json.Unmarshal([]byte(secretJSON), &secretData); err != nil {
		return fmt.Errorf("解析密钥失败: %w", err)
	}

	// 验证 TOTP
	if !totp.Validate(req.Code, secretData.Secret) {
		return errors.New("验证码错误")
	}

	// 启用凭证
	now := time.Now()
	if err := s.db.WithContext(ctx).Model(&credential).Updates(map[string]any{
		"enabled":      true,
		"last_used_at": now,
	}).Error; err != nil {
		return fmt.Errorf("启用凭证失败: %w", err)
	}

	logger.Infof("[Credential] TOTP 绑定成功 - OpenID: %s", req.OpenID)
	return nil
}

// VerifyTOTPRequest TOTP 验证请求
type VerifyTOTPRequest struct {
	OpenID string // 用户标识
	Code   string // 验证码
}

// VerifyTOTP 验证 TOTP
func (s *CredentialService) VerifyTOTP(ctx context.Context, req *VerifyTOTPRequest) error {
	// 获取启用的 TOTP 凭证
	var credential models.UserCredential
	err := s.db.WithContext(ctx).
		Where("openid = ? AND type = ? AND enabled = ?", req.OpenID, models.CredentialTypeTOTP, true).
		First(&credential).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("用户未绑定 TOTP")
		}
		return fmt.Errorf("查询凭证失败: %w", err)
	}

	// 解密密钥
	encKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return fmt.Errorf("获取加密密钥失败: %w", err)
	}

	secretJSON, err := cryptoutil.Decrypt(encKey, credential.Secret, req.OpenID)
	if err != nil {
		return fmt.Errorf("解密密钥失败: %w", err)
	}

	var secretData models.TOTPSecret
	if err := json.Unmarshal([]byte(secretJSON), &secretData); err != nil {
		return fmt.Errorf("解析密钥失败: %w", err)
	}

	// 验证 TOTP
	if !totp.Validate(req.Code, secretData.Secret) {
		return errors.New("验证码错误")
	}

	// 更新最后使用时间
	now := time.Now()
	if err := s.db.WithContext(ctx).Model(&credential).Update("last_used_at", now).Error; err != nil {
		logger.Warnf("[Credential] 更新 TOTP 最后使用时间失败: %v", err)
	}

	return nil
}

// DisableTOTP 禁用 TOTP
func (s *CredentialService) DisableTOTP(ctx context.Context, openid string) error {
	result := s.db.WithContext(ctx).
		Where("openid = ? AND type = ?", openid, models.CredentialTypeTOTP).
		Delete(&models.UserCredential{})
	if result.Error != nil {
		return fmt.Errorf("删除凭证失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.New("用户未绑定 TOTP")
	}
	logger.Infof("[Credential] TOTP 已禁用 - OpenID: %s", openid)
	return nil
}

// HasTOTP 检查用户是否已绑定 TOTP
func (s *CredentialService) HasTOTP(ctx context.Context, openid string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.UserCredential{}).
		Where("openid = ? AND type = ? AND enabled = ?", openid, models.CredentialTypeTOTP, true).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// SetTOTPEnabled 设置 TOTP 启用状态
func (s *CredentialService) SetTOTPEnabled(ctx context.Context, openid string, enabled bool) error {
	result := s.db.WithContext(ctx).Model(&models.UserCredential{}).
		Where("openid = ? AND type = ?", openid, models.CredentialTypeTOTP).
		Update("enabled", enabled)
	if result.Error != nil {
		return fmt.Errorf("更新凭证失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.New("用户未绑定 TOTP")
	}
	logger.Infof("[Credential] TOTP 启用状态已更新 - OpenID: %s, Enabled: %v", openid, enabled)
	return nil
}

// ==================== WebAuthn 相关 ====================

// RegisterWebAuthnRequest WebAuthn 注册请求
type RegisterWebAuthnRequest struct {
	OpenID          string   // 用户标识
	CredentialID    string   // Base64 编码的凭证 ID
	PublicKey       string   // Base64 编码的公钥
	AAGUID          string   // 认证器 GUID
	Transport       []string // 传输方式
	AttestationType string   // 认证类型
}

// RegisterWebAuthn 注册 WebAuthn 凭证
func (s *CredentialService) RegisterWebAuthn(ctx context.Context, req *RegisterWebAuthnRequest) (*models.UserCredential, error) {
	// 检查凭证 ID 是否已存在
	var existing models.UserCredential
	err := s.db.WithContext(ctx).Where("credential_id = ?", req.CredentialID).First(&existing).Error
	if err == nil {
		return nil, errors.New("凭证已存在")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("查询凭证失败: %w", err)
	}

	// 构建 WebAuthn 密钥数据
	secretData := &models.WebAuthnSecret{
		PublicKey:       req.PublicKey,
		SignCount:       0,
		AAGUID:          req.AAGUID,
		Transport:       req.Transport,
		AttestationType: req.AttestationType,
	}
	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		return nil, fmt.Errorf("序列化密钥失败: %w", err)
	}

	// 加密存储
	encKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return nil, fmt.Errorf("获取加密密钥失败: %w", err)
	}

	encryptedSecret, err := cryptoutil.Encrypt(encKey, string(secretJSON), req.OpenID)
	if err != nil {
		return nil, fmt.Errorf("加密密钥失败: %w", err)
	}

	// 保存凭证
	credential := &models.UserCredential{
		OpenID:       req.OpenID,
		CredentialID: &req.CredentialID,
		Type:         string(models.CredentialTypeWebAuthn),
		Enabled:      true, // WebAuthn 注册后即启用
		Secret:       encryptedSecret,
	}

	if err := s.db.WithContext(ctx).Create(credential).Error; err != nil {
		return nil, fmt.Errorf("保存凭证失败: %w", err)
	}

	logger.Infof("[Credential] WebAuthn 注册成功 - OpenID: %s, CredentialID: %s...", req.OpenID, req.CredentialID[:16])
	return credential, nil
}

// GetWebAuthnByCredentialID 根据凭证 ID 获取 WebAuthn 凭证
func (s *CredentialService) GetWebAuthnByCredentialID(ctx context.Context, credentialID string) (*models.UserCredential, *models.WebAuthnSecret, error) {
	var credential models.UserCredential
	err := s.db.WithContext(ctx).
		Where("credential_id = ? AND type = ? AND enabled = ?", credentialID, models.CredentialTypeWebAuthn, true).
		First(&credential).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, errors.New("凭证不存在")
		}
		return nil, nil, fmt.Errorf("查询凭证失败: %w", err)
	}

	// 解密
	encKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return nil, nil, fmt.Errorf("获取加密密钥失败: %w", err)
	}

	secretJSON, err := cryptoutil.Decrypt(encKey, credential.Secret, credential.OpenID)
	if err != nil {
		return nil, nil, fmt.Errorf("解密密钥失败: %w", err)
	}

	var secretData models.WebAuthnSecret
	if err := json.Unmarshal([]byte(secretJSON), &secretData); err != nil {
		return nil, nil, fmt.Errorf("解析密钥失败: %w", err)
	}

	return &credential, &secretData, nil
}

// UpdateWebAuthnSignCount 更新 WebAuthn 签名计数
func (s *CredentialService) UpdateWebAuthnSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	credential, secretData, err := s.GetWebAuthnByCredentialID(ctx, credentialID)
	if err != nil {
		return err
	}

	// 检查签名计数（防止重放攻击）
	if signCount <= secretData.SignCount {
		return errors.New("签名计数异常，可能存在重放攻击")
	}

	// 更新签名计数
	secretData.SignCount = signCount
	secretJSON, err := json.Marshal(secretData)
	if err != nil {
		return fmt.Errorf("序列化密钥失败: %w", err)
	}

	encKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return fmt.Errorf("获取加密密钥失败: %w", err)
	}

	encryptedSecret, err := cryptoutil.Encrypt(encKey, string(secretJSON), credential.OpenID)
	if err != nil {
		return fmt.Errorf("加密密钥失败: %w", err)
	}

	now := time.Now()
	if err := s.db.WithContext(ctx).Model(credential).Updates(map[string]any{
		"secret":       encryptedSecret,
		"last_used_at": now,
	}).Error; err != nil {
		return fmt.Errorf("更新凭证失败: %w", err)
	}

	return nil
}

// ListUserWebAuthn 获取用户所有 WebAuthn 凭证
func (s *CredentialService) ListUserWebAuthn(ctx context.Context, openid string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	err := s.db.WithContext(ctx).
		Where("openid = ? AND type IN (?, ?) AND enabled = ?", openid, models.CredentialTypeWebAuthn, models.CredentialTypePasskey, true).
		Find(&credentials).Error
	if err != nil {
		return nil, fmt.Errorf("查询凭证失败: %w", err)
	}
	return credentials, nil
}

// DeleteWebAuthn 删除 WebAuthn 凭证
func (s *CredentialService) DeleteWebAuthn(ctx context.Context, openid string, credentialID string) error {
	result := s.db.WithContext(ctx).
		Where("openid = ? AND credential_id = ?", openid, credentialID).
		Delete(&models.UserCredential{})
	if result.Error != nil {
		return fmt.Errorf("删除凭证失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.New("凭证不存在")
	}
	logger.Infof("[Credential] WebAuthn 已删除 - OpenID: %s", openid)
	return nil
}

// SetWebAuthnEnabled 设置 WebAuthn 启用状态
func (s *CredentialService) SetWebAuthnEnabled(ctx context.Context, openid string, credentialID string, enabled bool) error {
	result := s.db.WithContext(ctx).Model(&models.UserCredential{}).
		Where("openid = ? AND credential_id = ?", openid, credentialID).
		Update("enabled", enabled)
	if result.Error != nil {
		return fmt.Errorf("更新凭证失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.New("凭证不存在")
	}
	logger.Infof("[Credential] WebAuthn 启用状态已更新 - OpenID: %s, CredentialID: %s, Enabled: %v", openid, credentialID, enabled)
	return nil
}

// ==================== 通用接口 ====================

// ListUserCredentials 获取用户所有凭证
func (s *CredentialService) ListUserCredentials(ctx context.Context, openid string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	err := s.db.WithContext(ctx).
		Where("openid = ? AND enabled = ?", openid, true).
		Find(&credentials).Error
	if err != nil {
		return nil, fmt.Errorf("查询凭证失败: %w", err)
	}
	return credentials, nil
}

// GetUserCredentialSummaries 获取用户凭证摘要列表
func (s *CredentialService) GetUserCredentialSummaries(ctx context.Context, openid string) ([]models.CredentialSummary, error) {
	credentials, err := s.ListUserCredentials(ctx, openid)
	if err != nil {
		return nil, err
	}

	summaries := make([]models.CredentialSummary, len(credentials))
	for i, cred := range credentials {
		summary := models.CredentialSummary{
			ID:         cred.ID,
			Type:       cred.Type,
			Enabled:    cred.Enabled,
			LastUsedAt: cred.LastUsedAt,
			CreatedAt:  cred.CreatedAt,
		}
		if cred.CredentialID != nil {
			// 只显示部分凭证 ID（安全考虑）
			credID := *cred.CredentialID
			if len(credID) > 16 {
				summary.CredentialID = credID[:16] + "..."
			} else {
				summary.CredentialID = credID
			}
		}
		summaries[i] = summary
	}

	return summaries, nil
}

// GetUserMFAStatus 获取用户 MFA 状态
func (s *CredentialService) GetUserMFAStatus(ctx context.Context, openid string) (*models.MFAStatus, error) {
	credentials, err := s.ListUserCredentials(ctx, openid)
	if err != nil {
		return nil, err
	}

	status := &models.MFAStatus{}
	for _, cred := range credentials {
		switch models.CredentialType(cred.Type) {
		case models.CredentialTypeTOTP:
			status.TOTPEnabled = true
		case models.CredentialTypeWebAuthn:
			status.WebAuthnCount++
		case models.CredentialTypePasskey:
			status.PasskeyCount++
		}
	}

	return status, nil
}

// GetPublicKeyForCredential 获取 WebAuthn 凭证的公钥（用于验证签名）
func (s *CredentialService) GetPublicKeyForCredential(ctx context.Context, credentialID string) ([]byte, error) {
	_, secretData, err := s.GetWebAuthnByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(secretData.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("解码公钥失败: %w", err)
	}

	return publicKey, nil
}
