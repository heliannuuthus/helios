package main

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/chaos"
	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/pkg/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

func main() {
	config.LoadConfig()
	config.LoadHermes()
	config.LoadChaos()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()

	db := hermesconfig.InitDB()
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
