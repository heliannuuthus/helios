package main

import (
	"fmt"

	"github.com/gin-gonic/gin"

	chaosconfig "github.com/heliannuuthus/chaos/config"
	chaos "github.com/heliannuuthus/chaos/internal"
	"github.com/heliannuuthus/pkg/aegis/guard"
	"github.com/heliannuuthus/pkg/config"
	"github.com/heliannuuthus/pkg/logger"
)

func main() {
	config.LoadChaos()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()
	initTokenManager()

	db := chaosconfig.InitDB()
	app, err := chaos.New(db)
	if err != nil {
		logger.Fatalf("初始化 chaos 失败: %v", err)
	}

	if !config.IsDebug() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()
	r.RedirectTrailingSlash = false

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	app.Handler().RegisterRoutes(r)

	addr := fmt.Sprintf(":%d", config.GetServerPort())
	logger.Infof("chaos 服务启动: %s", addr)
	if err := r.Run(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}

func initTokenManager() {
	seed, err := chaosconfig.GetAegisSecretKeyBytes()
	if err != nil {
		logger.Fatalf("初始化 Chaos token manager 失败: %v", err)
	}
	if err := guard.NewServiceTokenManager(chaosconfig.GetAegisIssuer(), chaosconfig.GetAegisAudience(), seed); err != nil {
		logger.Fatalf("初始化 Chaos token manager 失败: %v", err)
	}
}
