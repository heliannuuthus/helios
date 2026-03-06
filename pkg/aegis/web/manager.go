package web

import (
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

var globalManager *token.Manager

// NewTokenManager 初始化全局 token Manager。应在服务启动时调用一次。
func NewTokenManager(endpoint string, seedProvider key.Provider) {
	globalManager = token.NewManager(endpoint, seedProvider)
}

// GetTokenManager 返回全局 token Manager。
func GetTokenManager() *token.Manager {
	return globalManager
}
