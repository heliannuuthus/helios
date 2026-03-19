package dto

import (
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== Domain ====================

// DomainUpdateRequest 更新域请求（JSON Merge Patch 语义，仅 name、description 可编辑）
type DomainUpdateRequest struct {
	Name        patch.Optional[string] `json:"name"`
	Description patch.Optional[string] `json:"description"`
}

// DomainResponse 域基础信息（名称、描述等）；allowed_idps 不在此暴露，需时调 GET /domains/:id/idps）
type DomainResponse struct {
	DomainID    string  `json:"domain_id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// ==================== Service ====================

// ServiceCreateRequest 创建服务请求（服务仅控制 access_token 有效期）
type ServiceCreateRequest struct {
	ServiceID            string  `json:"service_id" binding:"required"`
	DomainID             string  `json:"domain_id" binding:"required"`
	Name                 string  `json:"name" binding:"required"`
	Description          string  `json:"description" binding:"required"`
	LogoURL              *string `json:"logo_url"`
	AccessTokenExpiresIn *uint   `json:"access_token_expires_in"`
}

// ServiceUpdateRequest 更新服务请求（JSON Merge Patch 语义）
type ServiceUpdateRequest struct {
	Name                 patch.Optional[string] `json:"name"`
	Description          patch.Optional[string] `json:"description"`
	LogoURL              patch.Optional[string] `json:"logo_url"`
	AccessTokenExpiresIn patch.Optional[uint]   `json:"access_token_expires_in"`
}

// ServiceResponse 服务（无 _id，仅 access_token 有效期由服务控制）
type ServiceResponse struct {
	ServiceID            string  `json:"service_id"`
	DomainID             string  `json:"domain_id"`
	Name                 string  `json:"name"`
	Description          *string `json:"description,omitempty"`
	LogoURL              *string `json:"logo_url,omitempty"`
	AccessTokenExpiresIn uint    `json:"access_token_expires_in"`
	CreatedAt            string  `json:"created_at"`
	UpdatedAt            string  `json:"updated_at"`
}

func NewServiceResponse(s *models.Service, domainID string) ServiceResponse {
	effectiveDomainID := s.DomainID
	if effectiveDomainID == models.CrossDomainID {
		effectiveDomainID = domainID
	}
	return ServiceResponse{
		ServiceID:            s.ServiceID,
		DomainID:             effectiveDomainID,
		Name:                 s.Name,
		Description:          s.Description,
		LogoURL:              s.LogoURL,
		AccessTokenExpiresIn: s.AccessTokenExpiresIn,
		CreatedAt:            FormatTime(s.CreatedAt),
		UpdatedAt:            FormatTime(s.UpdatedAt),
	}
}

// ==================== Application ====================

// ApplicationCreateRequest 创建应用请求（应用控制 id_token、refresh_token 有效期）
// AppID 可选；不填时后端用随机 bigint 经 base62 编码自动生成
type ApplicationCreateRequest struct {
	DomainID                      string   `json:"domain_id" binding:"required"`
	AppID                         string   `json:"app_id"`
	Name                          string   `json:"name" binding:"required"`
	Description                   string   `json:"description" binding:"required"`
	AllowedRedirectURIs           []string `json:"allowed_redirect_uris"`
	AllowedOrigins                []string `json:"allowed_origins"`
	AllowedLogoutURIs             []string `json:"allowed_logout_uris"`
	NeedKey                       bool     `json:"need_key"`
	IDTokenExpiresIn              *uint    `json:"id_token_expires_in"`
	RefreshTokenExpiresIn         *uint    `json:"refresh_token_expires_in"`
	RefreshTokenAbsoluteExpiresIn *uint    `json:"refresh_token_absolute_expires_in"`
}

// ApplicationUpdateRequest 更新应用请求（JSON Merge Patch 语义）
type ApplicationUpdateRequest struct {
	Name                          patch.Optional[string]   `json:"name"`
	Description                   patch.Optional[string]   `json:"description"`
	LogoURL                       patch.Optional[string]   `json:"logo_url"`
	AllowedRedirectURIs           patch.Optional[[]string] `json:"allowed_redirect_uris"`
	AllowedOrigins                patch.Optional[[]string] `json:"allowed_origins"`
	AllowedLogoutURIs             patch.Optional[[]string] `json:"allowed_logout_uris"`
	IDTokenExpiresIn              patch.Optional[uint]     `json:"id_token_expires_in"`
	RefreshTokenExpiresIn         patch.Optional[uint]     `json:"refresh_token_expires_in"`
	RefreshTokenAbsoluteExpiresIn patch.Optional[uint]     `json:"refresh_token_absolute_expires_in"`
}

// ApplicationResponse 应用（无 _id，allowed_redirect_uris/allowed_origins 为数组）
type ApplicationResponse struct {
	DomainID                      string   `json:"domain_id"`
	AppID                         string   `json:"app_id"`
	Name                          string   `json:"name"`
	Description                   *string  `json:"description,omitempty"`
	LogoURL                       *string  `json:"logo_url,omitempty"`
	AllowedRedirectURIs           []string `json:"allowed_redirect_uris,omitempty"`
	AllowedOrigins                []string `json:"allowed_origins,omitempty"`
	AllowedLogoutURIs             []string `json:"allowed_logout_uris,omitempty"`
	IDTokenExpiresIn              uint     `json:"id_token_expires_in"`
	RefreshTokenExpiresIn         uint     `json:"refresh_token_expires_in"`
	RefreshTokenAbsoluteExpiresIn uint     `json:"refresh_token_absolute_expires_in"`
	CreatedAt                     string   `json:"created_at"`
	UpdatedAt                     string   `json:"updated_at"`
}

func NewApplicationResponse(a *models.Application) ApplicationResponse {
	return ApplicationResponse{
		DomainID:                      a.DomainID,
		AppID:                         a.AppID,
		Name:                          a.Name,
		Description:                   a.Description,
		LogoURL:                       a.LogoURL,
		AllowedRedirectURIs:           ParseJSONStringSlice(a.AllowedRedirectURIs),
		AllowedOrigins:                ParseJSONStringSlice(a.AllowedOrigins),
		AllowedLogoutURIs:             ParseJSONStringSlice(a.AllowedLogoutURIs),
		IDTokenExpiresIn:              a.IDTokenExpiresIn,
		RefreshTokenExpiresIn:         a.RefreshTokenExpiresIn,
		RefreshTokenAbsoluteExpiresIn: a.RefreshTokenAbsoluteExpiresIn,
		CreatedAt:                     FormatTime(a.CreatedAt),
		UpdatedAt:                     FormatTime(a.UpdatedAt),
	}
}

// ==================== IDP Config ====================

// DomainIDPConfigCreateRequest 创建域 IDP 配置请求
type DomainIDPConfigCreateRequest struct {
	IDPType  string  `json:"idp_type" binding:"required"`
	Priority int     `json:"priority"`
	Strategy *string `json:"strategy,omitempty"`
	TAppID   string  `json:"t_app_id" binding:"required"`
}

// DomainIDPConfigUpdateRequest 更新域 IDP 配置请求（JSON Merge Patch 语义）
type DomainIDPConfigUpdateRequest struct {
	Priority patch.Optional[int]    `json:"priority"`
	Strategy patch.Optional[string] `json:"strategy"`
	TAppID   patch.Optional[string] `json:"t_app_id"`
}

// DomainIDPConfigResponse 域 IDP 配置（无 _id，t_secret 不暴露）
type DomainIDPConfigResponse struct {
	DomainID  string  `json:"domain_id"`
	IDPType   string  `json:"idp_type"`
	Priority  int     `json:"priority"`
	Strategy  *string `json:"strategy,omitempty"`
	TAppID    string  `json:"t_app_id"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

func NewDomainIDPConfigResponse(c *models.DomainIDPConfig) DomainIDPConfigResponse {
	return DomainIDPConfigResponse{
		DomainID:  c.DomainID,
		IDPType:   c.IDPType,
		Priority:  c.Priority,
		Strategy:  c.Strategy,
		TAppID:    c.TAppID,
		CreatedAt: FormatTime(c.CreatedAt),
		UpdatedAt: FormatTime(c.UpdatedAt),
	}
}

// ApplicationIDPConfigCreateRequest 创建应用 IDP 配置请求（idp 类型必须在应用所属域的 allowed_idps 内）
type ApplicationIDPConfigCreateRequest struct {
	Type     string  `json:"type" binding:"required"`
	Priority int     `json:"priority"`
	Strategy *string `json:"strategy,omitempty"`
	TAppID   *string `json:"t_app_id,omitempty"`
}

// ApplicationIDPConfigUpdateRequest 更新应用 IDP 配置请求（JSON Merge Patch 语义）
type ApplicationIDPConfigUpdateRequest struct {
	Priority patch.Optional[int]    `json:"priority"`
	Strategy patch.Optional[string] `json:"strategy"`
	TAppID   patch.Optional[string] `json:"t_app_id"`
}

// ApplicationIDPConfigResponse 应用 IDP 配置（无 _id，t_secret 不暴露）
type ApplicationIDPConfigResponse struct {
	AppID     string  `json:"app_id"`
	Type      string  `json:"type"`
	Priority  int     `json:"priority"`
	Strategy  *string `json:"strategy,omitempty"`
	TAppID    *string `json:"t_app_id,omitempty"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}
