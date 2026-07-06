package models

import (
	"strings"
	"time"
)

// ApplicationIDPConfig 应用 IDP 配置（从 proto 转换）
type ApplicationIDPConfig struct {
	ID        uint      `json:"_id"`
	AppID     string    `json:"app_id"`
	Type      string    `json:"type"`
	Priority  int       `json:"priority"`
	Strategy  *string   `json:"strategy,omitempty"`
	Delegate  *string   `json:"delegate,omitempty"`
	Require   *string   `json:"require,omitempty"`
	TAppID    *string   `json:"t_app_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GetStrategyList 解析 strategy 列表
func (a *ApplicationIDPConfig) GetStrategyList() []string {
	if a.Strategy == nil || *a.Strategy == "" {
		return nil
	}
	return strings.Split(*a.Strategy, ",")
}

// GetDelegateList 解析 delegate 列表
func (a *ApplicationIDPConfig) GetDelegateList() []string {
	if a.Delegate == nil || *a.Delegate == "" {
		return nil
	}
	return strings.Split(*a.Delegate, ",")
}

// GetRequireList 解析 require 列表
func (a *ApplicationIDPConfig) GetRequireList() []string {
	if a.Require == nil || *a.Require == "" {
		return nil
	}
	return strings.Split(*a.Require, ",")
}

// ApplicationServiceRelation 应用服务关系（从 proto 转换）
type ApplicationServiceRelation struct {
	ID        uint      `json:"_id"`
	AppID     string    `json:"app_id"`
	ServiceID string    `json:"service_id"`
	Relation  string    `json:"relation"`
	CreatedAt time.Time `json:"created_at"`
}
