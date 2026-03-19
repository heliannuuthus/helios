package dto

import (
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// IDPKeyCreateRequest 创建 IDP 密钥
type IDPKeyCreateRequest struct {
	IDPType string `json:"idp_type" binding:"required"`
	TAppID  string `json:"t_app_id" binding:"required"`
	TSecret string `json:"t_secret" binding:"required"`
}

// IDPKeyUpdateRequest 更新 IDP 密钥（JSON Merge Patch 语义）
type IDPKeyUpdateRequest struct {
	TSecret patch.Optional[string] `json:"t_secret"`
}

// IDPKeyResponse IDP 密钥（不暴露 t_secret）
type IDPKeyResponse struct {
	IDPType   string `json:"idp_type"`
	TAppID    string `json:"t_app_id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func NewIDPKeyResponse(s *models.IDPKey) IDPKeyResponse {
	return IDPKeyResponse{
		IDPType:   s.IDPType,
		TAppID:    s.TAppID,
		CreatedAt: FormatTime(s.CreatedAt),
		UpdatedAt: FormatTime(s.UpdatedAt),
	}
}
