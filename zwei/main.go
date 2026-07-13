package main

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/pkg/aegis/guard"
	"github.com/heliannuuthus/pkg/config"
	"github.com/heliannuuthus/pkg/logger"
	zweiconfig "github.com/heliannuuthus/zwei/config"
	zwei "github.com/heliannuuthus/zwei/internal"
)

// @title Helios API
// @version 1.0
// @description Helios 统一后端 API - 提供认证、业务和身份与访问管理服务
// @host localhost:18000
// @BasePath /api
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description 输入 "Bearer {token}"
func main() {
	config.LoadZwei()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()
	if err := zweiconfig.Validate(); err != nil {
		logger.Fatalf("Zwei 配置校验失败: %v", err)
	}
	initTokenManager()

	db := zweiconfig.InitDB()
	app, err := zwei.New(db)
	if err != nil {
		logger.Fatalf("初始化 Zwei 失败: %v", err)
	}

	if !config.IsDebug() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()
	r.RedirectTrailingSlash = false

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	app.RegisterRoutes(r)

	addr := fmt.Sprintf(":%d", config.GetServerPort())
	logger.Infof("zwei 服务启动: %s", addr)
	if err := r.Run(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}

func initTokenManager() {
	seed, err := zweiconfig.GetAegisSecretKeyBytes()
	if err != nil {
		logger.Fatalf("初始化 Zwei token manager 失败: %v", err)
	}
	if err := guard.NewServiceTokenManager(zweiconfig.GetAegisIssuer(), zweiconfig.GetAegisAudience(), seed); err != nil {
		logger.Fatalf("初始化 Zwei token manager 失败: %v", err)
	}
}
