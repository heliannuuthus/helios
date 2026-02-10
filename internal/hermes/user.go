package hermes

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/bcrypt"
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

// GetByOpenID 根据 OpenID 查找用户
func (s *UserService) GetByOpenID(ctx context.Context, openid string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("openid = ?", openid).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByIdentity 根据身份模型查找用户（使用 domain + idp + t_openid 定位）
func (s *UserService) GetByIdentity(ctx context.Context, identity *models.UserIdentity) (*models.User, error) {
	var matched models.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("domain = ? AND idp = ? AND t_openid = ?", identity.Domain, identity.IDP, identity.TOpenID).
		First(&matched).Error; err != nil {
		return nil, err
	}

	return s.GetByOpenID(ctx, matched.OpenID)
}

// GetIdentitiesByIdentity 根据身份模型查找该用户的全部身份
// 用户不存在返回空切片（非 error），仅基础设施故障才返回 error
func (s *UserService) GetIdentitiesByIdentity(ctx context.Context, identity *models.UserIdentity) (models.Identities, error) {
	var matched models.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("domain = ? AND idp = ? AND t_openid = ?", identity.Domain, identity.IDP, identity.TOpenID).
		First(&matched).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return s.GetIdentities(ctx, matched.OpenID)
}

// getByEmail 根据邮箱查找用户（内部使用，返回基础 User）
func (s *UserService) getByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByEmail 根据邮箱查找用户（返回解密后的完整用户信息）
func (s *UserService) GetByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error) {
	user, err := s.getByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return s.GetUserWithDecrypted(ctx, user.OpenID)
}

// GetIdentityByType 获取用户指定域和 IDP 类型的身份
func (s *UserService) GetIdentityByType(ctx context.Context, domain, openid, idpType string) (*models.UserIdentity, error) {
	var identity models.UserIdentity
	if err := s.db.WithContext(ctx).Where("domain = ? AND openid = ? AND idp = ?", domain, openid, idpType).First(&identity).Error; err != nil {
		return nil, err
	}
	return &identity, nil
}

// GetByUsername 根据用户名查找用户
func (s *UserService) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByPhone 根据手机号哈希查找用户
func (s *UserService) GetByPhone(ctx context.Context, phoneHash string) (*models.User, error) {
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

// CreateWithIdentities 创建用户及多个身份关联（事务）
func (s *UserService) CreateWithIdentities(ctx context.Context, user *models.User, identities models.Identities) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("创建用户失败: %w", err)
		}

		for _, identity := range identities {
			identity.OpenID = user.OpenID
			if err := tx.Create(identity).Error; err != nil {
				return fmt.Errorf("创建身份关联失败: %w", err)
			}
		}

		return nil
	})
}

// Update 更新用户
func (s *UserService) Update(ctx context.Context, openid string, updates map[string]any) error {
	return s.db.WithContext(ctx).Model(&models.User{}).Where("openid = ?", openid).Updates(updates).Error
}

// UpdateLastLogin 更新最后登录时间
func (s *UserService) UpdateLastLogin(ctx context.Context, openid string) error {
	return s.Update(ctx, openid, map[string]any{"last_login_at": time.Now()})
}

// UpdatePassword 修改用户密码（验证旧密码后更新）
func (s *UserService) UpdatePassword(ctx context.Context, openid, oldPassword, newPassword string) error {
	user, err := s.GetByOpenID(ctx, openid)
	if err != nil {
		return errors.New("user not found")
	}

	// 如果用户已设置密码，必须验证旧密码
	if user.PasswordHash != nil && *user.PasswordHash != "" {
		if oldPassword == "" {
			return errors.New("old password is required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(oldPassword)); err != nil {
			return errors.New("old password is incorrect")
		}
	}

	// 哈希新密码
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password failed: %w", err)
	}

	hashStr := string(hash)
	return s.Update(ctx, openid, map[string]any{"password_hash": hashStr})
}

// AddIdentity 添加身份关联
func (s *UserService) AddIdentity(ctx context.Context, identity *models.UserIdentity) error {
	return s.db.WithContext(ctx).Create(identity).Error
}

// GetIdentities 获取用户所有身份关联
func (s *UserService) GetIdentities(ctx context.Context, openid string) (models.Identities, error) {
	var identities models.Identities
	if err := s.db.WithContext(ctx).Where("openid = ?", openid).Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// GetUserWithDecrypted 获取解密后的用户（解密手机号）
func (s *UserService) GetUserWithDecrypted(ctx context.Context, openid string) (*models.UserWithDecrypted, error) {
	user, err := s.GetByOpenID(ctx, openid)
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

// GetUserWithDecryptedByIdentity 根据身份模型获取解密后的用户
func (s *UserService) GetUserWithDecryptedByIdentity(ctx context.Context, identity *models.UserIdentity) (*models.UserWithDecrypted, error) {
	user, err := s.GetByIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}

	return s.GetUserWithDecrypted(ctx, user.OpenID)
}

// CreateUser 创建用户及其身份关联（认证身份 + global 身份）
// openid 在此处生成一次，同时作为 t_user.openid 和 global identity 的 t_openid
func (s *UserService) CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (*models.UserWithDecrypted, error) {
	now := time.Now()
	openid := models.GenerateOpenID()

	// 优先使用 IDP 提供的用户信息，否则生成随机值
	var nickname, picture string
	if userInfo != nil && userInfo.Nickname != "" {
		nickname = userInfo.Nickname
	} else {
		nickname = generateRandomName()
	}
	if userInfo != nil && userInfo.Picture != "" {
		picture = userInfo.Picture
	} else {
		picture = generateRandomAvatar(identity.TOpenID)
	}

	newUser := &models.User{
		OpenID:      openid,
		Nickname:    &nickname,
		Picture:     &picture,
		LastLoginAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 如果 IDP 提供了邮箱，设置并标记为已验证
	if userInfo != nil && userInfo.Email != "" {
		newUser.Email = &userInfo.Email
		newUser.EmailVerified = true
	}

	// 认证身份
	authIdentity := &models.UserIdentity{
		Domain:    identity.Domain,
		IDP:       identity.IDP,
		TOpenID:   identity.TOpenID,
		RawData:   identity.RawData,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 全局身份（该域下的对外标识，t_openid = openid）
	globalIdentity := &models.UserIdentity{
		Domain:    identity.Domain,
		IDP:       "global",
		TOpenID:   openid,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.CreateWithIdentities(ctx, newUser, models.Identities{authIdentity, globalIdentity}); err != nil {
		return nil, err
	}

	logger.Infof("[UserService] 创建新用户 - Domain: %s, OpenID: %s, IDP: %s", identity.Domain, openid, identity.IDP)

	return &models.UserWithDecrypted{User: *newUser}, nil
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
func (s *UserService) GetUserCredentials(ctx context.Context, openid string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ?", openid).Find(&credentials).Error; err != nil {
		return nil, err
	}
	return credentials, nil
}

// GetUserCredentialsByType 获取用户指定类型的凭证
func (s *UserService) GetUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ? AND type = ?", openid, credType).Find(&credentials).Error; err != nil {
		return nil, err
	}
	return credentials, nil
}

// GetEnabledUserCredentialsByType 获取用户已启用的指定类型的凭证
func (s *UserService) GetEnabledUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ? AND type = ? AND enabled = ?", openid, credType, true).Find(&credentials).Error; err != nil {
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
func (s *UserService) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	return s.db.WithContext(ctx).Where("openid = ? AND credential_id = ?", openid, credentialID).Delete(&models.UserCredential{}).Error
}

// GetOpenIDByCredentialID 根据凭证 ID 获取用户 OpenID
func (s *UserService) GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	cred, err := s.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return "", err
	}
	return cred.OpenID, nil
}

// ==================== PasswordStore 接口实现（供 password IDP 使用）====================

// PasswordStoreCredential 密码存储凭证信息
type PasswordStoreCredential struct {
	OpenID       string // 该 IDP 身份的 TOpenID，由 toPasswordStoreCredentialWithIDP 设置
	PasswordHash string // 密码哈希（bcrypt）
	Nickname     string // 昵称
	Email        string // 邮箱
	Picture      string // 头像
	Status       int8   // 用户状态
}

// GetUserByIdentifier 根据标识符获取 C 端用户凭证信息
// identifier 可以是用户名、邮箱或手机号
// 通过 identity 表中 idp=user 的记录确认用户具有 C 端身份
func (s *UserService) GetUserByIdentifier(ctx context.Context, identifier string) (*PasswordStoreCredential, error) {
	return s.getByIdentifierWithIDP(ctx, identifier, "user")
}

// GetOperByIdentifier 根据标识符获取 B 端运营人员凭证信息
// identifier 通常是用户名
// 通过 identity 表中 idp=oper 的记录确认用户具有 B 端身份
func (s *UserService) GetOperByIdentifier(ctx context.Context, identifier string) (*PasswordStoreCredential, error) {
	return s.getByIdentifierWithIDP(ctx, identifier, "oper")
}

// getByIdentifierWithIDP 根据标识符查找用户，并验证用户具有指定 IDP 的主身份
func (s *UserService) getByIdentifierWithIDP(ctx context.Context, identifier, idpType string) (*PasswordStoreCredential, error) {
	// 按优先级尝试不同的标识符类型
	// 1. 尝试用户名
	user, err := s.GetByUsername(ctx, identifier)
	if err == nil {
		return s.toPasswordStoreCredentialWithIDP(ctx, user, idpType)
	}

	// 2. 尝试邮箱（如果标识符包含 @）
	if isEmail(identifier) {
		userByEmail, err := s.getByEmail(ctx, identifier)
		if err == nil {
			return s.toPasswordStoreCredentialWithIDP(ctx, userByEmail, idpType)
		}
	}

	// 3. 尝试手机号（如果是纯数字）
	if isPhone(identifier) {
		phoneHash := hashPhone(identifier)
		userByPhone, err := s.GetByPhone(ctx, phoneHash)
		if err == nil {
			return s.toPasswordStoreCredentialWithIDP(ctx, userByPhone, idpType)
		}
	}

	return nil, errors.New("user not found")
}

// toPasswordStoreCredentialWithIDP 转换为密码存储凭证，同时验证用户具有指定 IDP 的身份
func (s *UserService) toPasswordStoreCredentialWithIDP(ctx context.Context, user *models.User, idpType string) (*PasswordStoreCredential, error) {
	// 查找用户在该 IDP 类型下的身份（任意域均可）
	var identity models.UserIdentity
	if err := s.db.WithContext(ctx).Where("openid = ? AND idp = ?", user.OpenID, idpType).First(&identity).Error; err != nil {
		return nil, errors.New("user not found")
	}

	cred := s.toPasswordStoreCredential(user)
	// 使用该身份的 TOpenID 作为对外标识
	cred.OpenID = identity.TOpenID
	return cred, nil
}

// toPasswordStoreCredential 转换为密码存储凭证
func (s *UserService) toPasswordStoreCredential(user *models.User) *PasswordStoreCredential {
	cred := &PasswordStoreCredential{
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
