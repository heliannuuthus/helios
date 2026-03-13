package main

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/heliannuuthus/aegis-go/guard"
	reqr "github.com/heliannuuthus/aegis-go/guard/requirement"
	"github.com/heliannuuthus/aegis-go/utilities/key"
	"github.com/heliannuuthus/aegis-go/utilities/relation"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	aegisconfig "github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/middleware"
	_ "github.com/heliannuuthus/helios/docs"
	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	irisconfig "github.com/heliannuuthus/helios/iris/config"
	"github.com/heliannuuthus/helios/pkg/config"
	"github.com/heliannuuthus/helios/pkg/logger"
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
	// 加载所有配置
	config.Load()

	// 初始化日志
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()

	// 初始化全局 token Manager
	initTokenManager()

	// 通过 Wire 初始化应用
	app, err := InitializeApp()
	if err != nil {
		logger.Fatalf("初始化应用失败: %v", err)
	}

	// 设置 Gin 模式
	if !config.IsDebug() {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建 Gin 引擎
	r := gin.Default()
	r.RedirectTrailingSlash = false

	// 根路径
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": config.GetAppName(),
			"version": config.GetAppVersion(),
		})
	})

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Swagger 文档
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Aegis CORS 中间件（支持应用配置的 allowed_origins，SPA 跨域调用需要）
	aegisCORS := middleware.CORS(app.AegisHandler.CacheManager())

	// Aegis 认证路由（OAuth2.1/OIDC 风格）
	authGroup := r.Group("/auth")
	{
		// 需要 CORS 的路由（aegis-ui / 业务前端 SPA 跨域调用）
		corsRoutes := []struct {
			method, path string
			handler      gin.HandlerFunc
		}{
			{"POST", "/authorize", app.AegisHandler.Authorize},
			{"GET", "/connections", app.AegisHandler.GetConnections},
			{"GET", "/context", app.AegisHandler.GetContext},
			{"POST", "/login", app.AegisHandler.Login},
			{"GET", "/binding", app.AegisHandler.GetIdentifyContext},
			{"POST", "/binding", app.AegisHandler.ConfirmIdentify},
			{"POST", "/challenge", app.AegisHandler.InitiateChallenge},
			{"POST", "/challenge/:cid", app.AegisHandler.ContinueChallenge},
			{"POST", "/token", app.AegisHandler.Token},
			{"POST", "/revoke", app.AegisHandler.Revoke},
			{"POST", "/logout", app.AegisHandler.Logout},
			{"GET", "/logout", app.AegisHandler.LogoutGET},
			{"GET", "/pubkeys", app.AegisHandler.PublicKeys},
		}
		registered := make(map[string]bool)
		for _, route := range corsRoutes {
			authGroup.Handle(route.method, route.path, aegisCORS, route.handler)
			if !registered[route.path] {
				authGroup.OPTIONS(route.path, aegisCORS)
				registered[route.path] = true
			}
		}

		// 服务端调用的接口（不需要 CORS）
		authGroup.POST("/check", app.AegisHandler.Check)
	}

	// Iris 用户信息路由
	irisGuard := guard.NewGin(irisconfig.GetAegisAudience())
	userGroup := r.Group("/user")
	{
		userRoutes := []struct {
			method, path string
			handler      gin.HandlerFunc
		}{
			{"GET", "/profile", app.IrisHandler.GetProfile},
			{"PATCH", "/profile", app.IrisHandler.UpdateProfile},
			{"POST", "/profile/avatar", app.IrisHandler.UploadAvatar},
			{"PUT", "/profile/email", app.IrisHandler.UpdateEmail},
			{"PUT", "/profile/phone", app.IrisHandler.UpdatePhone},
			{"GET", "/identities", app.IrisHandler.ListIdentities},
			{"POST", "/identities/:idp", app.IrisHandler.BindIdentity},
			{"DELETE", "/identities/:idp", app.IrisHandler.UnbindIdentity},
			{"GET", "/mfa", app.IrisHandler.GetMFAStatus},
			{"POST", "/mfa", app.IrisHandler.SetupMFA},
			{"PUT", "/mfa", app.IrisHandler.VerifyMFA},
			{"PATCH", "/mfa", app.IrisHandler.UpdateMFA},
			{"DELETE", "/mfa", app.IrisHandler.DeleteMFA},
		}
		registered := make(map[string]bool)
		for _, route := range userRoutes {
			userGroup.Handle(route.method, route.path, aegisCORS, irisGuard.Require(), route.handler)
			if !registered[route.path] {
				userGroup.OPTIONS(route.path, aegisCORS)
				registered[route.path] = true
			}
		}
	}

	// Zwei 业务 API 路由
	app.Zwei.RegisterRoutes(r)

	// Hermes 身份与访问管理路由
	hermesAud := hermesconfig.GetAegisAudience()
	hermesGuard := guard.NewGin(hermesAud)
	adminRelation := hermesGuard.Require(reqr.Relation(relation.Qualify("admin", "service:"+hermesAud)))
	hermes := r.Group("/hermes")
	hermes.Use(hermesGuard.Require())
	{
		// 域管理
		domains := hermes.Group("/domains")
		{
			domains.GET("", app.HermesHandler.ListDomains)
			domains.GET("/:domain_id", app.HermesHandler.GetDomain)
			domains.PATCH("/:domain_id", adminRelation, app.HermesHandler.UpdateDomain)
			domains.GET("/:domain_id/idps", app.HermesHandler.GetDomainAllowedIDPs)

			// 域下服务：domains/:domain_id/services
			domainServices := domains.Group("/:domain_id/services")
			{
				domainServices.GET("", app.HermesHandler.ListServices)
				domainServices.GET("/:service_id", app.HermesHandler.GetService)
				domainServices.GET("/:service_id/applications", app.HermesHandler.GetServiceApplicationRelations)
				domainServices.GET("/:service_id/applications/:app_id/relations", app.HermesHandler.GetServiceAppRelations)
				domainServices.PUT("/:service_id/applications/:app_id/relations", adminRelation, app.HermesHandler.SetServiceAppRelations)
				domainServices.POST("", adminRelation, app.HermesHandler.CreateService)
				domainServices.PATCH("/:service_id", adminRelation, app.HermesHandler.UpdateService)
				domainServices.DELETE("/:service_id", adminRelation, app.HermesHandler.DeleteService)
			}

			// 域下应用：domains/:domain_id/applications
			domainApps := domains.Group("/:domain_id/applications")
			{
				domainApps.GET("", app.HermesHandler.ListApplications)
				domainApps.GET("/:app_id", app.HermesHandler.GetApplication)
				domainApps.GET("/:app_id/relations", app.HermesHandler.GetApplicationServiceRelations)
				domainApps.GET("/:app_id/idp-configs", app.HermesHandler.ListApplicationIDPConfigs)
				domainApps.POST("", adminRelation, app.HermesHandler.CreateApplication)
				domainApps.PATCH("/:app_id", adminRelation, app.HermesHandler.UpdateApplication)
				domainApps.POST("/:app_id/idp-configs", adminRelation, app.HermesHandler.CreateApplicationIDPConfig)
				domainApps.PATCH("/:app_id/idp-configs/:idp_type", adminRelation, app.HermesHandler.UpdateApplicationIDPConfig)
				domainApps.DELETE("/:app_id/idp-configs/:idp_type", adminRelation, app.HermesHandler.DeleteApplicationIDPConfig)

				appServices := domainApps.Group("/:app_id/services/:service_id")
				{
					appServices.GET("/relationships", app.HermesHandler.ListAppServiceRelationships)
					appServices.POST("/relationships", adminRelation, app.HermesHandler.CreateAppServiceRelationship)
					appServices.PATCH("/relationships/:relationship_id", adminRelation, app.HermesHandler.UpdateAppServiceRelationship)
					appServices.DELETE("/relationships/:relationship_id", adminRelation, app.HermesHandler.DeleteAppServiceRelationship)
				}
			}
		}

		// 关系管理
		relationships := hermes.Group("/relationships")
		{
			relationships.GET("", app.HermesHandler.ListRelationships)
			relationships.POST("", adminRelation, app.HermesHandler.CreateRelationship)
			relationships.PATCH("", adminRelation, app.HermesHandler.UpdateRelationship)
			relationships.DELETE("", adminRelation, app.HermesHandler.DeleteRelationship)
		}

		// 组管理
		groups := hermes.Group("/groups")
		{
			groups.GET("", app.HermesHandler.ListGroups)
			groups.GET("/:group_id", app.HermesHandler.GetGroup)
			groups.GET("/:group_id/members", app.HermesHandler.GetGroupMembers)
			groups.POST("", adminRelation, app.HermesHandler.CreateGroup)
			groups.PATCH("/:group_id", adminRelation, app.HermesHandler.UpdateGroup)
			groups.POST("/:group_id/members", adminRelation, app.HermesHandler.SetGroupMembers)
		}
	}

	// Chaos 业务聚合服务路由
	app.ChaosHandler.RegisterRoutes(r)

	// 启动服务器
	addr := fmt.Sprintf("%s:%d", config.GetServerHost(), config.GetServerPort())
	logger.Infof("服务启动: http://%s", addr)
	logger.Infof("API 文档: http://%s/swagger/index.html", addr)

	if err := r.Run(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}

func initTokenManager() {
	masterKey, err := hermesconfig.GetAegisSecretKeyBytes()
	if err != nil {
		logger.Fatalf("获取 aegis secret key 失败: %v", err)
	}
	endpoint := aegisconfig.GetIssuer()
	seed := key.SingleOf(func(_ context.Context, _ string) ([]byte, error) {
		return masterKey, nil
	})
	guard.NewTokenManager(endpoint, seed)
}
