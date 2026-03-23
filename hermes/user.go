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

	"github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	cryptoutil "github.com/heliannuuthus/helios/pkg/crypto"
	"github.com/heliannuuthus/helios/pkg/filter"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== User CRUD ====================

// GetUserByOpenID 根据 OpenID 查找用户
func (s *Service) GetUserByOpenID(ctx context.Context, openid string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("openid = ?", openid).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByIdentity 根据身份定位查找用户（domain + idp + t_openid）
func (s *Service) GetUserByIdentity(ctx context.Context, domain, idp, tOpenID string) (*models.User, error) {
	var matched models.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("domain = ? AND idp = ? AND t_openid = ?", domain, idp, tOpenID).
		First(&matched).Error; err != nil {
		return nil, err
	}
	return s.GetUserByOpenID(ctx, matched.UID)
}

// GetUserByEmail 根据邮箱查找用户（返回解密后的完整用户信息）
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error) {
	user, err := s.getUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return s.GetDecryptedUserByOpenID(ctx, user.OpenID)
}

// GetUserByUsername 根据用户名查找用户（最左模糊匹配）
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("username LIKE ?", username+"%").First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByPhone 根据手机号明文查找用户（内部哈希后查询，返回解密后的完整用户信息）
func (s *Service) GetUserByPhone(ctx context.Context, phone string) (*models.UserWithDecrypted, error) {
	phoneHash := hashPhone(phone)
	var user models.User
	if err := s.db.WithContext(ctx).Where("phone = ?", phoneHash).First(&user).Error; err != nil {
		return nil, err
	}
	return s.GetDecryptedUserByOpenID(ctx, user.OpenID)
}

// GetDecryptedUserByOpenID 获取解密后的用户（解密手机号）
func (s *Service) GetDecryptedUserByOpenID(ctx context.Context, openid string) (*models.UserWithDecrypted, error) {
	user, err := s.GetUserByOpenID(ctx, openid)
	if err != nil {
		return nil, err
	}

	result := &models.UserWithDecrypted{User: *user}

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

// GetDecryptedUserByIdentity 根据身份定位获取解密后的用户
func (s *Service) GetDecryptedUserByIdentity(ctx context.Context, domain, idp, tOpenID string) (*models.UserWithDecrypted, error) {
	user, err := s.GetUserByIdentity(ctx, domain, idp, tOpenID)
	if err != nil {
		return nil, err
	}
	return s.GetDecryptedUserByOpenID(ctx, user.OpenID)
}

// ==================== Identity 相关 ====================

// GetIdentities 根据 domain + idp + t_openid 查找该用户的全部身份
// 用户不存在返回空切片（非 error），仅基础设施故障才返回 error
func (s *Service) GetIdentities(ctx context.Context, domain, idp, tOpenID string) (models.Identities, error) {
	var matched models.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("domain = ? AND idp = ? AND t_openid = ?", domain, idp, tOpenID).
		First(&matched).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return s.GetUserIdentitiesByOpenID(ctx, matched.UID)
}

// GetUserIdentitiesByOpenID 获取用户所有身份关联
func (s *Service) GetUserIdentitiesByOpenID(ctx context.Context, openid string) (models.Identities, error) {
	var identities models.Identities
	if err := s.db.WithContext(ctx).Where("uid = ?", openid).Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// GetUserIdentityByType 获取用户指定域和 IDP 类型的身份
func (s *Service) GetUserIdentityByType(ctx context.Context, domain, openid, idpType string) (*models.UserIdentity, error) {
	var identity models.UserIdentity
	if err := s.db.WithContext(ctx).Where("domain = ? AND uid = ? AND idp = ?", domain, openid, idpType).First(&identity).Error; err != nil {
		return nil, err
	}
	return &identity, nil
}

// AddIdentity 添加身份关联
func (s *Service) AddIdentity(ctx context.Context, identity *models.UserIdentity) error {
	return s.db.WithContext(ctx).Create(identity).Error
}

// ==================== User Write ====================

// CreateUser 创建用户及其身份关联（认证身份 + global 身份）
func (s *Service) CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (*models.UserWithDecrypted, error) {
	now := time.Now()
	openid := models.GenerateOpenID()

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

	if userInfo != nil && userInfo.Email != "" {
		newUser.Email = &userInfo.Email
		newUser.EmailVerified = true
	}

	authIdentity := &models.UserIdentity{
		Domain:    identity.Domain,
		IDP:       identity.IDP,
		TOpenID:   identity.TOpenID,
		RawData:   identity.RawData,
		CreatedAt: now,
		UpdatedAt: now,
	}

	globalIdentity := &models.UserIdentity{
		Domain:    identity.Domain,
		IDP:       "global",
		TOpenID:   openid,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.createWithIdentities(ctx, newUser, models.Identities{authIdentity, globalIdentity}); err != nil {
		return nil, err
	}

	logger.Infof("[UserService] 创建新用户 - Domain: %s, OpenID: %s, IDP: %s", identity.Domain, openid, identity.IDP)
	return &models.UserWithDecrypted{User: *newUser}, nil
}

// createWithIdentities 创建用户及多个身份关联（事务）
func (s *Service) createWithIdentities(ctx context.Context, user *models.User, identities models.Identities) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("创建用户失败: %w", err)
		}
		for _, identity := range identities {
			identity.UID = user.OpenID
			if err := tx.Create(identity).Error; err != nil {
				return fmt.Errorf("创建身份关联失败: %w", err)
			}
		}
		return nil
	})
}

// UpdateUser 更新用户
func (s *Service) UpdateUser(ctx context.Context, openid string, updates map[string]any) error {
	return s.db.WithContext(ctx).Model(&models.User{}).Where("openid = ?", openid).Updates(updates).Error
}

// UpdateLastLogin 更新最后登录时间
func (s *Service) UpdateLastLogin(ctx context.Context, openid string) error {
	return s.UpdateUser(ctx, openid, map[string]any{"last_login_at": time.Now()})
}

// UpdatePassword 修改用户密码（验证旧密码后更新）
func (s *Service) UpdatePassword(ctx context.Context, openid, oldPassword, newPassword string) error {
	user, err := s.GetUserByOpenID(ctx, openid)
	if err != nil {
		return errors.New("user not found")
	}

	if user.PasswordHash != nil && *user.PasswordHash != "" {
		if oldPassword == "" {
			return errors.New("old password is required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(oldPassword)); err != nil {
			return errors.New("old password is incorrect")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password failed: %w", err)
	}

	hashStr := string(hash)
	return s.UpdateUser(ctx, openid, map[string]any{"password_hash": hashStr})
}

// ==================== WebAuthn 凭证管理 ====================

// CreateCredential 创建凭证（TOTP 类型自动加密 Secret）
func (s *Service) CreateCredential(ctx context.Context, cred *models.UserCredential) error {
	if models.CredentialType(cred.Type) == models.CredentialTypeTOTP && cred.Secret != "" {
		encrypted, err := s.encryptSecret(cred.Secret, cred.OpenID)
		if err != nil {
			return fmt.Errorf("加密凭证失败: %w", err)
		}
		cred.Secret = encrypted
	}
	return s.db.WithContext(ctx).Create(cred).Error
}

// GetCredentialByID 根据凭证 ID 获取凭证（TOTP 类型自动解密 Secret）
func (s *Service) GetCredentialByID(ctx context.Context, credentialID string) (*models.UserCredential, error) {
	var cred models.UserCredential
	if err := s.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&cred).Error; err != nil {
		return nil, err
	}
	s.decryptCredentialSecret(&cred)
	return &cred, nil
}

// GetUserCredentials 获取用户所有凭证（TOTP 类型自动解密 Secret）
func (s *Service) GetUserCredentials(ctx context.Context, openid string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ?", openid).Find(&credentials).Error; err != nil {
		return nil, err
	}
	s.decryptCredentialSecrets(credentials)
	return credentials, nil
}

// GetUserCredentialsByType 获取用户指定类型的凭证（TOTP 类型自动解密 Secret）
func (s *Service) GetUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ? AND type = ?", openid, credType).Find(&credentials).Error; err != nil {
		return nil, err
	}
	s.decryptCredentialSecrets(credentials)
	return credentials, nil
}

// GetEnabledUserCredentialsByType 获取用户已启用的指定类型的凭证（TOTP 类型自动解密 Secret）
func (s *Service) GetEnabledUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error) {
	var credentials []models.UserCredential
	if err := s.db.WithContext(ctx).Where("openid = ? AND type = ? AND enabled = ?", openid, credType, true).Find(&credentials).Error; err != nil {
		return nil, err
	}
	s.decryptCredentialSecrets(credentials)
	return credentials, nil
}

// UpdateCredential 更新凭证
func (s *Service) UpdateCredential(ctx context.Context, credentialID string, updates map[string]any) error {
	return s.db.WithContext(ctx).Model(&models.UserCredential{}).Where("credential_id = ?", credentialID).Updates(updates).Error
}

// UpdateCredentialSignCount 更新凭证签名计数
func (s *Service) UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	return s.UpdateCredential(ctx, credentialID, map[string]any{
		"secret":       gorm.Expr("JSON_SET(secret, '$.sign_count', ?)", signCount),
		"last_used_at": time.Now(),
	})
}

// EnableCredential 启用凭证
func (s *Service) EnableCredential(ctx context.Context, credentialID string) error {
	return s.UpdateCredential(ctx, credentialID, map[string]any{"enabled": true})
}

// DisableCredential 禁用凭证
func (s *Service) DisableCredential(ctx context.Context, credentialID string) error {
	return s.UpdateCredential(ctx, credentialID, map[string]any{"enabled": false})
}

// DeleteCredential 删除凭证
func (s *Service) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	return s.db.WithContext(ctx).Where("openid = ? AND credential_id = ?", openid, credentialID).Delete(&models.UserCredential{}).Error
}

// GetOpenIDByCredentialID 根据凭证 ID 获取用户 OpenID
func (s *Service) GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	cred, err := s.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return "", err
	}
	return cred.OpenID, nil
}

// GetCredentialByInternalID 根据内部主键 ID 获取凭证（TOTP 类型自动解密 Secret）
func (s *Service) GetCredentialByInternalID(ctx context.Context, id uint) (*models.UserCredential, error) {
	var cred models.UserCredential
	if err := s.db.WithContext(ctx).Where("_id = ?", id).First(&cred).Error; err != nil {
		return nil, err
	}
	s.decryptCredentialSecret(&cred)
	return &cred, nil
}

// UpdateCredentialByInternalID 根据内部主键 ID 更新凭证
func (s *Service) UpdateCredentialByInternalID(ctx context.Context, id uint, updates map[string]any) error {
	return s.db.WithContext(ctx).Model(&models.UserCredential{}).Where("_id = ?", id).Updates(updates).Error
}

// DeleteCredentialByOpenIDAndType 根据 openid 和类型删除凭证
func (s *Service) DeleteCredentialByOpenIDAndType(ctx context.Context, openid string, credType string) error {
	return s.db.WithContext(ctx).Where("openid = ? AND type = ?", openid, credType).Delete(&models.UserCredential{}).Error
}

// ==================== PasswordStore 接口实现（供 password IDP 使用）====================

// GetUserByIdentifier 根据标识符获取 C 端用户凭证信息
func (s *Service) GetUserByIdentifier(ctx context.Context, identifier string) (*dto.PasswordStoreCredential, error) {
	return s.getByIdentifierWithIDP(ctx, identifier, "user")
}

// GetStaffByIdentifier 根据标识符获取 B 端平台人员凭证信息
func (s *Service) GetStaffByIdentifier(ctx context.Context, identifier string) (*dto.PasswordStoreCredential, error) {
	return s.getByIdentifierWithIDP(ctx, identifier, "staff")
}

// getUserByEmail 根据邮箱查找用户（内部使用，返回基础 User）
func (s *Service) getUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// getByIdentifierWithIDP 根据标识符查找用户，并验证用户具有指定 IDP 的主身份
func (s *Service) getByIdentifierWithIDP(ctx context.Context, identifier, idpType string) (*dto.PasswordStoreCredential, error) {
	// 1. 尝试用户名（最左模糊匹配）
	user, err := s.GetUserByUsername(ctx, identifier)
	if err == nil {
		return s.toPasswordStoreCredentialWithIDP(ctx, user, idpType)
	}

	// 2. 尝试邮箱
	if isEmail(identifier) {
		userByEmail, err := s.getUserByEmail(ctx, identifier)
		if err == nil {
			return s.toPasswordStoreCredentialWithIDP(ctx, userByEmail, idpType)
		}
	}

	// 3. 尝试手机号
	if isPhone(identifier) {
		phoneHash := hashPhone(identifier)
		var userByPhone models.User
		if err := s.db.WithContext(ctx).Where("phone = ?", phoneHash).First(&userByPhone).Error; err == nil {
			return s.toPasswordStoreCredentialWithIDP(ctx, &userByPhone, idpType)
		}
	}

	return nil, errors.New("user not found")
}

// toPasswordStoreCredentialWithIDP 转换为密码存储凭证，同时验证用户具有指定 IDP 的身份
func (s *Service) toPasswordStoreCredentialWithIDP(ctx context.Context, user *models.User, idpType string) (*dto.PasswordStoreCredential, error) {
	var identity models.UserIdentity
	if err := s.db.WithContext(ctx).Where("uid = ? AND idp = ?", user.OpenID, idpType).First(&identity).Error; err != nil {
		return nil, errors.New("user not found")
	}

	cred := s.toPasswordStoreCredential(user)
	cred.OpenID = identity.TOpenID
	return cred, nil
}

// toPasswordStoreCredential 转换为密码存储凭证
func (s *Service) toPasswordStoreCredential(user *models.User) *dto.PasswordStoreCredential {
	cred := &dto.PasswordStoreCredential{
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

// ==================== Group 相关 ====================

var groupFilters = filter.Whitelist{
	"service_id": {filter.Eq},
	"name":       {filter.Eq},
}

// CreateGroup 创建组
func (s *Service) CreateGroup(ctx context.Context, req *dto.GroupCreateRequest) (*models.Group, error) {
	group := &models.Group{
		GroupID:     req.GroupID,
		ServiceID:   req.ServiceID,
		Name:        req.Name,
		Description: req.Description,
	}
	if err := s.db.WithContext(ctx).Create(group).Error; err != nil {
		return nil, fmt.Errorf("创建组失败: %w", err)
	}
	return group, nil
}

// GetGroup 获取组
func (s *Service) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	var group models.Group
	if err := s.db.WithContext(ctx).Where("group_id = ?", groupID).First(&group).Error; err != nil {
		return nil, err
	}
	return &group, nil
}

// ListGroups 列出组（游标分页）
func (s *Service) ListGroups(ctx context.Context, req *dto.ListRequest) (*pagination.Items[models.Group], error) {
	query := s.db.WithContext(ctx).Model(&models.Group{})
	query = filter.Apply(query, req.Filter, groupFilters)
	return pagination.CursorPaginate[models.Group](query, req.Pagination)
}

// UpdateGroup 更新组（JSON Merge Patch 语义）
func (s *Service) UpdateGroup(ctx context.Context, groupID string, req *dto.GroupUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("name", req.Name),
		patch.Field("description", req.Description),
	)
	if len(updates) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Model(&models.Group{}).Where("group_id = ?", groupID).Updates(updates).Error
}

// DeleteGroup 删除组（级联删除成员关系）
func (s *Service) DeleteGroup(ctx context.Context, groupID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("object_type = ? AND object_id = ? AND relation = ?", "group", groupID, "member").
			Delete(&models.Relationship{}).Error; err != nil {
			return fmt.Errorf("删除组成员关系失败: %w", err)
		}
		if err := tx.Where("group_id = ?", groupID).Delete(&models.Group{}).Error; err != nil {
			return fmt.Errorf("删除组失败: %w", err)
		}
		return nil
	})
}

// SetGroupMembers 设置组成员（全量替换，通过 Relationship 表实现）
func (s *Service) SetGroupMembers(ctx context.Context, req *dto.GroupMemberRequest) error {
	group, err := s.GetGroup(ctx, req.GroupID)
	if err != nil {
		return fmt.Errorf("组不存在: %w", err)
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("service_id = ? AND object_type = ? AND object_id = ? AND relation = ?",
			group.ServiceID, "group", req.GroupID, "member").
			Delete(&models.Relationship{}).Error; err != nil {
			return fmt.Errorf("清空组成员失败: %w", err)
		}
		for _, uid := range req.UserIDs {
			rel := &models.Relationship{
				ServiceID:   group.ServiceID,
				SubjectType: "user",
				SubjectID:   uid,
				Relation:    "member",
				ObjectType:  "group",
				ObjectID:    req.GroupID,
			}
			if err := tx.Create(rel).Error; err != nil {
				return fmt.Errorf("添加组成员失败: %w", err)
			}
		}
		return nil
	})
}

// GetGroupMembers 获取组成员列表
func (s *Service) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	var rels []models.Relationship
	if err := s.db.WithContext(ctx).
		Where("object_type = ? AND object_id = ? AND relation = ? AND subject_type = ?", "group", groupID, "member", "user").
		Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("获取组成员失败: %w", err)
	}
	userIDs := make([]string, 0, len(rels))
	for _, r := range rels {
		userIDs = append(userIDs, r.SubjectID)
	}
	return userIDs, nil
}

// ==================== helpers ====================

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

func isEmail(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}

func isPhone(s string) bool {
	if len(s) < 10 || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			if c == '+' && s[0] == '+' {
				continue
			}
			return false
		}
	}
	return true
}

func hashPhone(phone string) string {
	return cryptoutil.Hash(phone)
}

// ==================== 凭证加解密辅助 ====================

// encryptSecret 加密凭证密钥（AES-256-GCM，openid 作为 AAD）
func (s *Service) encryptSecret(plaintext, openid string) (string, error) {
	key, err := config.GetDBEncKeyRaw()
	if err != nil {
		return "", fmt.Errorf("获取加密密钥失败: %w", err)
	}
	return cryptoutil.Encrypt(key, plaintext, openid)
}

// decryptSecret 解密凭证密钥
func (s *Service) decryptSecret(ciphertext, openid string) (string, error) {
	key, err := config.GetDBEncKeyRaw()
	if err != nil {
		return "", fmt.Errorf("获取加密密钥失败: %w", err)
	}
	return cryptoutil.Decrypt(key, ciphertext, openid)
}

// decryptCredentialSecret 解密单个凭证的 Secret（仅 TOTP 类型）
func (s *Service) decryptCredentialSecret(cred *models.UserCredential) {
	if models.CredentialType(cred.Type) == models.CredentialTypeTOTP && cred.Secret != "" {
		plain, err := s.decryptSecret(cred.Secret, cred.OpenID)
		if err != nil {
			logger.Warnf("[UserService] 解密 TOTP 密钥失败 (ID=%d): %v", cred.ID, err)
			return
		}
		cred.Secret = plain
	}
}

// decryptCredentialSecrets 批量解密凭证的 Secret（仅 TOTP 类型）
func (s *Service) decryptCredentialSecrets(creds []models.UserCredential) {
	for i := range creds {
		s.decryptCredentialSecret(&creds[i])
	}
}
