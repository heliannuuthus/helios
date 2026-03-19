// Package adapter 提供 hermes → aegis/models 类型转换，
// 用于直连 DB 场景（非 gRPC）下将 hermes 层实现适配为 aegis/contract 接口。
package adapter

import (
	amodels "github.com/heliannuuthus/helios/aegis/models"
	hdto "github.com/heliannuuthus/helios/hermes/dto"
	hmodels "github.com/heliannuuthus/helios/hermes/models"
)

// ==================== Domain ====================

func ConvertDomain(d *hmodels.Domain) *amodels.Domain {
	if d == nil {
		return nil
	}
	return &amodels.Domain{
		DomainID:    d.DomainID,
		Name:        d.Name,
		Description: d.Description,
	}
}

// ==================== DomainIDPConfig ====================

func ConvertDomainIDPConfig(c *hmodels.DomainIDPConfig) *amodels.DomainIDPConfig {
	if c == nil {
		return nil
	}
	return &amodels.DomainIDPConfig{
		ID:       c.ID,
		DomainID: c.DomainID,
		IDPType:  c.IDPType,
		Priority: c.Priority,
		Strategy: c.Strategy,
		TAppID:   c.TAppID,
	}
}

func ConvertDomainIDPConfigs(cs []*hmodels.DomainIDPConfig) []*amodels.DomainIDPConfig {
	result := make([]*amodels.DomainIDPConfig, len(cs))
	for i, c := range cs {
		result[i] = ConvertDomainIDPConfig(c)
	}
	return result
}

// ==================== Application ====================

func ConvertApplication(a *hmodels.Application) *amodels.Application {
	if a == nil {
		return nil
	}
	return &amodels.Application{
		ID:                            a.ID,
		DomainID:                      a.DomainID,
		AppID:                         a.AppID,
		Name:                          a.Name,
		Description:                   a.Description,
		LogoURL:                       a.LogoURL,
		AllowedRedirectURIs:           a.AllowedRedirectURIs,
		AllowedOrigins:                a.AllowedOrigins,
		AllowedLogoutURIs:             a.AllowedLogoutURIs,
		IDTokenExpiresIn:              a.IDTokenExpiresIn,
		RefreshTokenExpiresIn:         a.RefreshTokenExpiresIn,
		RefreshTokenAbsoluteExpiresIn: a.RefreshTokenAbsoluteExpiresIn,
		CreatedAt:                     a.CreatedAt,
		UpdatedAt:                     a.UpdatedAt,
	}
}

// ==================== Service ====================

func ConvertService(s *hmodels.Service) *amodels.Service {
	if s == nil {
		return nil
	}
	cs := make([]amodels.ServiceChallengeSetting, len(s.ChallengeSettings))
	for i, c := range s.ChallengeSettings {
		cs[i] = ConvertChallengeSetting(c)
	}
	return &amodels.Service{
		ID:                   s.ID,
		DomainID:             s.DomainID,
		ServiceID:            s.ServiceID,
		Name:                 s.Name,
		Description:          s.Description,
		LogoURL:              s.LogoURL,
		AccessTokenExpiresIn: s.AccessTokenExpiresIn,
		RequiredIdentities:   s.RequiredIdentities,
		CreatedAt:            s.CreatedAt,
		UpdatedAt:            s.UpdatedAt,
		ChallengeSettings:    cs,
	}
}

func ConvertChallengeSetting(c hmodels.ServiceChallengeSetting) amodels.ServiceChallengeSetting {
	return amodels.ServiceChallengeSetting{
		ID:        c.ID,
		ServiceID: c.ServiceID,
		Type:      c.Type,
		ExpiresIn: c.ExpiresIn,
		Limits:    amodels.RateLimits(c.Limits),
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

func ConvertChallengeSettingPtr(c *hmodels.ServiceChallengeSetting) *amodels.ServiceChallengeSetting {
	if c == nil {
		return nil
	}
	r := ConvertChallengeSetting(*c)
	return &r
}

// ==================== ApplicationIDPConfig ====================

func ConvertIDPConfig(c *hmodels.ApplicationIDPConfig) *amodels.ApplicationIDPConfig {
	if c == nil {
		return nil
	}
	return &amodels.ApplicationIDPConfig{
		ID:        c.ID,
		AppID:     c.AppID,
		Type:      c.Type,
		Priority:  c.Priority,
		Strategy:  c.Strategy,
		TAppID:    c.TAppID,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

func ConvertIDPConfigs(cs []*hmodels.ApplicationIDPConfig) []*amodels.ApplicationIDPConfig {
	result := make([]*amodels.ApplicationIDPConfig, len(cs))
	for i, c := range cs {
		result[i] = ConvertIDPConfig(c)
	}
	return result
}

// ==================== ApplicationServiceRelation ====================

func ConvertRelation(r hmodels.ApplicationServiceRelation) amodels.ApplicationServiceRelation {
	return amodels.ApplicationServiceRelation{
		ID:        r.ID,
		AppID:     r.AppID,
		ServiceID: r.ServiceID,
		Relation:  r.Relation,
		CreatedAt: r.CreatedAt,
	}
}

func ConvertRelations(rs []hmodels.ApplicationServiceRelation) []amodels.ApplicationServiceRelation {
	result := make([]amodels.ApplicationServiceRelation, len(rs))
	for i, r := range rs {
		result[i] = ConvertRelation(r)
	}
	return result
}

// ==================== Relationship ====================

func ConvertRelationship(r hmodels.Relationship) amodels.Relationship {
	return amodels.Relationship{
		ID:          r.ID,
		ServiceID:   r.ServiceID,
		SubjectType: r.SubjectType,
		SubjectID:   r.SubjectID,
		Relation:    r.Relation,
		ObjectType:  r.ObjectType,
		ObjectID:    r.ObjectID,
		CreatedAt:   r.CreatedAt,
		ExpiresAt:   r.ExpiresAt,
	}
}

func ConvertRelationships(rs []hmodels.Relationship) []amodels.Relationship {
	result := make([]amodels.Relationship, len(rs))
	for i, r := range rs {
		result[i] = ConvertRelationship(r)
	}
	return result
}

// ==================== User ====================

func ConvertUserWithDecrypted(u *hmodels.UserWithDecrypted) *amodels.UserWithDecrypted {
	if u == nil {
		return nil
	}
	return &amodels.UserWithDecrypted{
		User: amodels.User{
			ID:            u.ID,
			OpenID:        u.OpenID,
			Status:        u.Status,
			Username:      u.Username,
			PasswordHash:  u.PasswordHash,
			Nickname:      u.Nickname,
			Picture:       u.Picture,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Phone:         u.User.Phone,
			PhoneCipher:   u.PhoneCipher,
			LastLoginAt:   u.LastLoginAt,
			CreatedAt:     u.CreatedAt,
			UpdatedAt:     u.UpdatedAt,
		},
		Phone: u.Phone,
	}
}

func ConvertIdentity(id hmodels.UserIdentity) amodels.UserIdentity {
	return amodels.UserIdentity{
		UID:       id.UID,
		Domain:    id.Domain,
		IDP:       id.IDP,
		TOpenID:   id.TOpenID,
		RawData:   id.RawData,
		CreatedAt: id.CreatedAt,
	}
}

func ConvertIdentityPtr(id *amodels.UserIdentity) *hmodels.UserIdentity {
	if id == nil {
		return nil
	}
	return &hmodels.UserIdentity{
		UID:       id.UID,
		Domain:    id.Domain,
		IDP:       id.IDP,
		TOpenID:   id.TOpenID,
		RawData:   id.RawData,
		CreatedAt: id.CreatedAt,
	}
}

func ConvertIdentities(ids hmodels.Identities) amodels.Identities {
	result := make(amodels.Identities, len(ids))
	for i, id := range ids {
		converted := ConvertIdentity(*id)
		result[i] = &converted
	}
	return result
}

func ConvertTUserInfo(info *amodels.TUserInfo) *hmodels.TUserInfo {
	if info == nil {
		return nil
	}
	return &hmodels.TUserInfo{
		TOpenID:  info.TOpenID,
		Nickname: info.Nickname,
		Email:    info.Email,
		Phone:    info.Phone,
		Picture:  info.Picture,
		RawData:  info.RawData,
	}
}

// ==================== Credential ====================

func ConvertCredential(c *hmodels.UserCredential) *amodels.UserCredential {
	if c == nil {
		return nil
	}
	return &amodels.UserCredential{
		ID:           c.ID,
		OpenID:       c.OpenID,
		CredentialID: c.CredentialID,
		Type:         c.Type,
		Enabled:      c.Enabled,
		LastUsedAt:   c.LastUsedAt,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		Secret:       c.Secret,
	}
}

func ConvertCredentialToHermes(c *amodels.UserCredential) *hmodels.UserCredential {
	if c == nil {
		return nil
	}
	return &hmodels.UserCredential{
		ID:           c.ID,
		OpenID:       c.OpenID,
		CredentialID: c.CredentialID,
		Type:         c.Type,
		Enabled:      c.Enabled,
		LastUsedAt:   c.LastUsedAt,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		Secret:       c.Secret,
	}
}

func ConvertCredentials(cs []hmodels.UserCredential) []amodels.UserCredential {
	result := make([]amodels.UserCredential, len(cs))
	for i := range cs {
		result[i] = *ConvertCredential(&cs[i])
	}
	return result
}

// ==================== PasswordStoreCredential ====================

func ConvertPasswordStoreCredential(c *hdto.PasswordStoreCredential) *amodels.PasswordStoreCredential {
	if c == nil {
		return nil
	}
	return &amodels.PasswordStoreCredential{
		OpenID:       c.OpenID,
		PasswordHash: c.PasswordHash,
		Nickname:     c.Nickname,
		Email:        c.Email,
		Picture:      c.Picture,
		Status:       c.Status,
	}
}
