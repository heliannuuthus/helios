package main

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/pkg/config"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/zwei"
	zweiconfig "github.com/heliannuuthus/helios/zwei/config"
)

func main() {
	config.LoadConfig()
	config.LoadZwei()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()

	db := zweiconfig.InitDB()
	app := zwei.New(db)

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
