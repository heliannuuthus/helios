package hermes

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	cryptoutil "github.com/heliannuuthus/helios/pkg/crypto"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// UserService 用户服务（连接数据库）
type UserService struct {
	db *gorm.DB
}

// NewUserService 创建用户服务
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// FindByOpenID 根据 OpenID 查找用户
func (s *UserService) FindByOpenID(ctx context.Context, openID string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("openid = ?", openID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByIdentity 根据 IDP + ProviderID 查找用户
func (s *UserService) FindByIdentity(ctx context.Context, idp, providerID string) (*models.User, error) {
	var identity models.UserIdentity
	if err := s.db.WithContext(ctx).Where("idp = ? AND t_openid = ?", idp, providerID).First(&identity).Error; err != nil {
		return nil, err
	}

	return s.FindByOpenID(ctx, identity.OpenID)
}

// findByEmail 根据邮箱查找用户（内部使用，返回基础 User）
func (s *UserService) findByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByEmail 根据邮箱查找用户（返回解密后的完整用户信息）
func (s *UserService) FindByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error) {
	user, err := s.findByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return s.GetUserWithDecrypted(ctx, user.OpenID)
}

// FindByEmailAndDomain 根据邮箱和域查找用户
func (s *UserService) FindByEmailAndDomain(ctx context.Context, email, domainID string) (*models.UserWithDecrypted, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("email = ? AND domain_id = ?", email, domainID).First(&user).Error; err != nil {
		return nil, err
	}
	return s.GetUserWithDecrypted(ctx, user.OpenID)
}

// FindByUsername 根据用户名查找用户
func (s *UserService) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByPhone 根据手机号哈希查找用户
func (s *UserService) FindByPhone(ctx context.Context, phoneHash string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("phone = ?", phoneHash).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// Create 创建用户
func (s *UserService) Create(ctx context.Context, user *models.User) error {
	return s.db.WithContext(ctx).Create(user).Error
}

// CreateWithIdentity 创建用户及身份关联（事务）
func (s *UserService) CreateWithIdentity(ctx context.Context, user *models.User, identity *models.UserIdentity) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("创建用户失败: %w", err)
		}

		identity.OpenID = user.OpenID
		if err := tx.Create(identity).Error; err != nil {
			return fmt.Errorf("创建身份关联失败: %w", err)
		}

		return nil
	})
}

// Update 更新用户
func (s *UserService) Update(ctx context.Context, openID string, updates map[string]any) error {
	return s.db.WithContext(ctx).Model(&models.User{}).Where("openid = ?", openID).Updates(updates).Error
}

// UpdateLastLogin 更新最后登录时间
func (s *UserService) UpdateLastLogin(ctx context.Context, openID string) error {
	return s.Update(ctx, openID, map[string]any{"last_login_at": time.Now()})
}

// AddIdentity 添加身份关联
func (s *UserService) AddIdentity(ctx context.Context, identity *models.UserIdentity) error {
	return s.db.WithContext(ctx).Create(identity).Error
}

// GetIdentities 获取用户所有身份关联
func (s *UserService) GetIdentities(ctx context.Context, openID string) ([]models.UserIdentity, error) {
	var identities []models.UserIdentity
	if err := s.db.WithContext(ctx).Where("openid = ?", openID).Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// GetUserWithDecrypted 获取解密后的用户（解密手机号）
func (s *UserService) GetUserWithDecrypted(ctx context.Context, openID string) (*models.UserWithDecrypted, error) {
	user, err := s.FindByOpenID(ctx, openID)
	if err != nil {
		return nil, err
	}

	result := &models.UserWithDecrypted{
		User: *user,
	}

	// 解密手机号
	if user.PhoneCipher != nil && *user.PhoneCipher != "" {
		key, err := config.GetDBEncKeyRaw()
		if err != nil {
			logger.Warnf("[UserService] 获取数据库加密密钥失败: %v", err)
		} else {
			phone, err := cryptoutil.Decrypt(key, *user.PhoneCipher, user.OpenID)
			if err != nil {
				logger.Warnf("[UserService] 解密手机号失败: %v", err)
			} else {
				result.Phone = phone
			}
		}
	}

	return result, nil
}

// GetUserWithDecryptedByIdentity 根据身份获取解密后的用户
func (s *UserService) GetUserWithDecryptedByIdentity(ctx context.Context, idp, providerID string) (*models.UserWithDecrypted, error) {
	user, err := s.FindByIdentity(ctx, idp, providerID)
	if err != nil {
		return nil, err
	}

	return s.GetUserWithDecrypted(ctx, user.OpenID)
}

// FindOrCreate 查找或创建用户
// 返回用户和是否为新创建
func (s *UserService) FindOrCreate(ctx context.Context, req *models.FindOrCreateUserRequest) (*models.UserWithDecrypted, bool, error) {
	// 1. 尝试通过身份查找
	user, err := s.FindByIdentity(ctx, req.IDP, req.ProviderID)
	if err == nil {
		// 找到用户，更新最后登录时间
		if err := s.UpdateLastLogin(ctx, user.OpenID); err != nil {
			logger.Warnf("[UserService] update last login failed: %v", err)
		}
		logger.Infof("[UserService] 找到已有用户 - OpenID: %s, IDP: %s", user.OpenID, req.IDP)

		result, err := s.GetUserWithDecrypted(ctx, user.OpenID)
		return result, false, err
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("查找用户失败: %w", err)
	}

	// 2. 创建新用户
	now := time.Now()

	// 优先使用 IDP 提供的用户信息，否则生成随机值
	var nickname, picture string
	if req.UserInfo != nil && req.UserInfo.Nickname != "" {
		nickname = req.UserInfo.Nickname
	} else {
		nickname = generateRandomName()
	}
	if req.UserInfo != nil && req.UserInfo.Picture != "" {
		picture = req.UserInfo.Picture
	} else {
		picture = generateRandomAvatar(req.ProviderID)
	}

	newUser := &models.User{
		OpenID:      models.GenerateOpenID(),
		DomainID:    req.DomainID,
		Nickname:    &nickname,
		Picture:     &picture,
		LastLoginAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 如果 IDP 提供了邮箱，设置并标记为已验证
	if req.UserInfo != nil && req.UserInfo.Email != "" {
		newUser.Email = &req.UserInfo.Email
		newUser.EmailVerified = true
	}

	identity := &models.UserIdentity{
		OpenID:    newUser.OpenID,
		IDP:       req.IDP,
		TOpenID:   req.ProviderID,
		RawData:   req.RawData,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.CreateWithIdentity(ctx, newUser, identity); err != nil {
		return nil, false, err
	}

	logger.Infof("[UserService] 创建新用户 - OpenID: %s, DomainID: %s, IDP: %s", newUser.OpenID, req.DomainID, req.IDP)

	result := &models.UserWithDecrypted{
		User: *newUser,
	}

	return result, true, nil
}

// generateRandomName 生成随机昵称
func generateRandomName() string {
	adjectives := []string{"快乐的", "聪明的", "勇敢的", "温柔的", "活泼的", "安静的", "优雅的", "幽默的"}
	nouns := []string{"小猫", "小狗", "小鸟", "小鱼", "小兔", "小熊", "小鹿", "小羊"}

	adjIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	if err != nil {
		panic(fmt.Sprintf("generate random name failed: %v", err))
	}
	nounIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))
	if err != nil {
		panic(fmt.Sprintf("generate random name failed: %v", err))
	}

	return adjectives[adjIndex.Int64()] + nouns[nounIndex.Int64()] + fmt.Sprintf("%04d", time.Now().Unix()%10000)
}

// generateRandomAvatar 生成随机头像
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

// ==================== WebAuthn 凭证管理 ====================

// CreateCredential 创建 WebAuthn 凭证
func (s *UserService) CreateCredential(ctx context.Context, cred *models.UserCredential) error {
	return s.db.WithContext(ctx).Create(cred).Error
}

// GetCredentialByID 根据凭证 ID 获取凭证
func (s *UserService) GetCredentialByID(ctx context.Context, credentialID string) (*models.UserCredential, error) {
	var cred models.UserCredential
	if err := s.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&cred).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}

// GetUserCredentials 获取用户所有凭证
func (s *UserService) GetUserCredentials(ctx context.Context, openID string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ?", openID).Find(&credentials).Error; err != nil {
		return nil, err
	}
	return credentials, nil
}

// GetUserCredentialsByType 获取用户指定类型的凭证
func (s *UserService) GetUserCredentialsByType(ctx context.Context, openID, credType string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ? AND type = ?", openID, credType).Find(&credentials).Error; err != nil {
		return nil, err
	}
	return credentials, nil
}

// GetEnabledUserCredentialsByType 获取用户已启用的指定类型的凭证
func (s *UserService) GetEnabledUserCredentialsByType(ctx context.Context, openID, credType string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ? AND type = ? AND enabled = ?", openID, credType, true).Find(&credentials).Error; err != nil {
		return nil, err
	}
	return credentials, nil
}

// UpdateCredential 更新凭证
func (s *UserService) UpdateCredential(ctx context.Context, credentialID string, updates map[string]any) error {
	return s.db.WithContext(ctx).Model(&models.UserCredential{}).Where("credential_id = ?", credentialID).Updates(updates).Error
}

// UpdateCredentialSignCount 更新凭证签名计数
func (s *UserService) UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	return s.UpdateCredential(ctx, credentialID, map[string]any{
		"secret":       gorm.Expr("JSON_SET(secret, '$.sign_count', ?)", signCount),
		"last_used_at": time.Now(),
	})
}

// EnableCredential 启用凭证
func (s *UserService) EnableCredential(ctx context.Context, credentialID string) error {
	return s.UpdateCredential(ctx, credentialID, map[string]any{"enabled": true})
}

// DisableCredential 禁用凭证
func (s *UserService) DisableCredential(ctx context.Context, credentialID string) error {
	return s.UpdateCredential(ctx, credentialID, map[string]any{"enabled": false})
}

// DeleteCredential 删除凭证
func (s *UserService) DeleteCredential(ctx context.Context, openID, credentialID string) error {
	return s.db.WithContext(ctx).Where("openid = ? AND credential_id = ?", openID, credentialID).Delete(&models.UserCredential{}).Error
}

// GetUserIDByCredentialID 根据凭证 ID 获取用户 OpenID
func (s *UserService) GetUserIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	cred, err := s.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return "", err
	}
	return cred.OpenID, nil
}

// ==================== PasswordStore 接口实现（供 password IDP 使用）====================

// PasswordStoreCredential 密码存储凭证信息
type PasswordStoreCredential struct {
	OpenID       string // 用户 OpenID
	PasswordHash string // 密码哈希（bcrypt）
	Nickname     string // 昵称
	Email        string // 邮箱
	Picture      string // 头像
	Status       int8   // 用户状态
}

// GetUserByIdentifier 根据标识符获取 C 端用户凭证信息
// identifier 可以是用户名、邮箱或手机号
// 只在 CIAM 域中查找
func (s *UserService) GetUserByIdentifier(ctx context.Context, identifier string) (*PasswordStoreCredential, error) {
	return s.getByIdentifierAndDomain(ctx, identifier, "ciam")
}

// GetOperByIdentifier 根据标识符获取 B 端运营人员凭证信息
// identifier 通常是用户名（oper 只支持用户名登录）
// 只在 PIAM 域中查找
func (s *UserService) GetOperByIdentifier(ctx context.Context, identifier string) (*PasswordStoreCredential, error) {
	return s.getByIdentifierAndDomain(ctx, identifier, "piam")
}

// getByIdentifierAndDomain 根据标识符和域获取凭证信息
func (s *UserService) getByIdentifierAndDomain(ctx context.Context, identifier, domainID string) (*PasswordStoreCredential, error) {
	// 按优先级尝试不同的标识符类型
	// 1. 尝试用户名
	user, err := s.findByUsernameAndDomain(ctx, identifier, domainID)
	if err == nil {
		return s.toPasswordStoreCredential(user), nil
	}

	// 2. 尝试邮箱（如果标识符包含 @）
	if isEmail(identifier) {
		userByEmail, err := s.findByEmailAndDomainInternal(ctx, identifier, domainID)
		if err == nil {
			return s.toPasswordStoreCredential(userByEmail), nil
		}
	}

	// 3. 尝试手机号（如果是纯数字）- 仅对 CIAM 有效
	if domainID == "ciam" && isPhone(identifier) {
		phoneHash := hashPhone(identifier)
		userByPhone, err := s.findByPhoneAndDomain(ctx, phoneHash, domainID)
		if err == nil {
			return s.toPasswordStoreCredential(userByPhone), nil
		}
	}

	return nil, errors.New("user not found")
}

// findByUsernameAndDomain 根据用户名和域查找
func (s *UserService) findByUsernameAndDomain(ctx context.Context, username, domainID string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("username = ? AND domain_id = ?", username, domainID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// findByEmailAndDomainInternal 根据邮箱和域查找（内部使用）
func (s *UserService) findByEmailAndDomainInternal(ctx context.Context, email, domainID string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("email = ? AND domain_id = ?", email, domainID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// findByPhoneAndDomain 根据手机号哈希和域查找
func (s *UserService) findByPhoneAndDomain(ctx context.Context, phoneHash, domainID string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("phone = ? AND domain_id = ?", phoneHash, domainID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// toPasswordStoreCredential 转换为密码存储凭证
func (s *UserService) toPasswordStoreCredential(user *models.User) *PasswordStoreCredential {
	cred := &PasswordStoreCredential{
		OpenID: user.OpenID,
		Status: user.Status,
	}

	if user.PasswordHash != nil {
		cred.PasswordHash = *user.PasswordHash
	}
	if user.Nickname != nil {
		cred.Nickname = *user.Nickname
	}
	if user.Email != nil {
		cred.Email = *user.Email
	}
	if user.Picture != nil {
		cred.Picture = *user.Picture
	}

	return cred
}

// isEmail 判断是否是邮箱格式
func isEmail(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}

// isPhone 判断是否是手机号格式（简单判断：纯数字且长度合理）
func isPhone(s string) bool {
	if len(s) < 10 || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			// 允许 + 号开头（国际号码）
			if c == '+' && s[0] == '+' {
				continue
			}
			return false
		}
	}
	return true
}

// hashPhone 对手机号进行哈希（用于查询）
func hashPhone(phone string) string {
	// 使用 SHA256 哈希手机号
	return cryptoutil.Hash(phone)
}
