package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	aegisconfig "github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/middleware"
	_ "github.com/heliannuuthus/helios/docs"
	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	irisconfig "github.com/heliannuuthus/helios/iris/config"
	"github.com/heliannuuthus/helios/pkg/config"
	"github.com/heliannuuthus/helios/pkg/logger"
	zweiconfig "github.com/heliannuuthus/helios/zwei/config"
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
	aegisCORS := middleware.CORSWithConfig(aegisconfig.Cfg(), app.AegisHandler.CacheManager())

	// Aegis 认证路由（OAuth2.1/OIDC 风格）
	authGroup := r.Group("/auth")
	{
		// 需要 CORS 的路由（aegis-ui / 业务前端 SPA 跨域调用）
		// CORS 中间件挂在每个路由上；OPTIONS 方法单独注册以处理 preflight
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
		authGroup.POST("/check", app.AegisHandler.Check)       // 关系检查（使用 CAT 认证）
		authGroup.GET("/pubkeys", app.AegisHandler.PublicKeys) // 获取 PASETO 公钥
	}

	// Iris 用户信息路由（需要 Iris 服务认证）
	// CORS: iris.heliannuuthus.com 前端使用 Bearer Token 跨域调用
	irisMw := app.MiddlewareFactory.WithAudience(irisconfig.GetAegisAudience())
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
			userGroup.Handle(route.method, route.path, aegisCORS, irisMw.RequireAuth(), route.handler)
			if !registered[route.path] {
				userGroup.OPTIONS(route.path, aegisCORS)
				registered[route.path] = true
			}
		}
	}

	// Zwei 业务 API 路由
	zweiMw := app.MiddlewareFactory.WithAudience(zweiconfig.GetAegisAudience())
	api := r.Group("/api")
	{
		// 菜谱路由（公开）
		recipes := api.Group("/recipes")
		{
			recipes.POST("", app.RecipeHandler.CreateRecipe)
			recipes.GET("", app.RecipeHandler.GetRecipes)
			recipes.GET("/categories/list", app.RecipeHandler.GetCategories)
			recipes.POST("/batch", app.RecipeHandler.CreateRecipesBatch)
			recipes.GET("/:recipe_id", app.RecipeHandler.GetRecipe)
			recipes.PATCH("/:recipe_id", app.RecipeHandler.UpdateRecipe)
			recipes.DELETE("/:recipe_id", app.RecipeHandler.DeleteRecipe)
		}

		// 用户相关路由（需要 Zwei audience 认证）
		user := api.Group("/user")
		{
			// 收藏路由
			favorites := user.Group("/favorites")
			favorites.Use(zweiMw.RequireAuth())
			{
				favorites.GET("", app.FavoriteHandler.GetFavorites)
				favorites.POST("", app.FavoriteHandler.AddFavorite)
				favorites.POST("/batch-check", app.FavoriteHandler.BatchCheckFavorites)
				favorites.GET("/:recipe_id/check", app.FavoriteHandler.CheckFavorite)
				favorites.DELETE("/:recipe_id", app.FavoriteHandler.RemoveFavorite)
			}

			// 浏览历史路由
			history := user.Group("/history")
			history.Use(zweiMw.RequireAuth())
			{
				history.GET("", app.HistoryHandler.GetViewHistory)
				history.POST("", app.HistoryHandler.AddViewHistory)
				history.DELETE("", app.HistoryHandler.ClearViewHistory)
				history.DELETE("/:recipe_id", app.HistoryHandler.RemoveViewHistory)
			}

			// 用户偏好路由
			preference := user.Group("/preference")
			{
				preference.GET("", zweiMw.RequireAuth(), app.PreferenceHandler.GetUserPreferences)
				preference.PUT("", zweiMw.RequireAuth(), app.PreferenceHandler.UpdateUserPreferences)
			}
		}

		// 首页路由（公开）
		home := api.Group("/home")
		{
			home.GET("/banners", app.HomeHandler.GetBanners)
			home.GET("/recommend", app.HomeHandler.GetRecommendRecipes)
			home.GET("/hot", app.HomeHandler.GetHotRecipes)
		}

		// 偏好选项路由（公开）
		api.GET("/preferences", app.PreferenceHandler.GetOptions)

		// 标签路由
		tags := api.Group("/tags")
		{
			tags.GET("", app.TagHandler.ListTags)
			tags.GET("/:type", app.TagHandler.GetTagsByType)
			tags.POST("", zweiMw.RequireAuth(), app.TagHandler.CreateTag)
			tags.PUT("/:type/:value", zweiMw.RequireAuth(), app.TagHandler.UpdateTag)
			tags.DELETE("/:type/:value", zweiMw.RequireAuth(), app.TagHandler.DeleteTag)
		}

		// 推荐路由
		recommend := api.Group("/recommend")
		{
			recommend.POST("", middleware.OptionalToken(app.Interpreter), app.RecommendHandler.GetRecommendations)
			recommend.POST("/context", zweiMw.RequireAuth(), app.RecommendHandler.GetContext)
		}

	}

	// Hermes 身份与访问管理路由
	// 使用 aegis 中间件进行认证
	hermesMw := app.MiddlewareFactory.WithAudience(hermesconfig.GetAegisAudience())
	hermes := r.Group("/hermes")
	hermes.Use(hermesMw.RequireAuth())
	{
		// 域管理
		domains := hermes.Group("/domains")
		{
			domains.GET("", app.HermesHandler.ListDomains)
			domains.GET("/:domain_id", app.HermesHandler.GetDomain)
		}

		// 服务管理
		services := hermes.Group("/services")
		{
			services.GET("", app.HermesHandler.ListServices)
			services.POST("", app.HermesHandler.CreateService)
			services.GET("/:service_id", app.HermesHandler.GetService)
			services.PATCH("/:service_id", app.HermesHandler.UpdateService)
		}

		// 应用管理
		applications := hermes.Group("/applications")
		{
			applications.GET("", app.HermesHandler.ListApplications)
			applications.POST("", app.HermesHandler.CreateApplication)
			applications.GET("/:app_id", app.HermesHandler.GetApplication)
			applications.PATCH("/:app_id", app.HermesHandler.UpdateApplication)
			applications.GET("/:app_id/applicable", app.HermesHandler.GetApplicationServiceRelations)
			applications.POST("/:app_id/services/:service_id/applicable", app.HermesHandler.SetApplicationServiceRelations)

			// 应用下的服务关系管理（RESTful 风格）
			appServices := applications.Group("/:app_id/services/:service_id")
			{
				appServices.GET("/relationships", app.HermesHandler.ListAppServiceRelationships)
				appServices.POST("/relationships", app.HermesHandler.CreateAppServiceRelationship)
				appServices.PATCH("/relationships/:relationship_id", app.HermesHandler.UpdateAppServiceRelationship)
				appServices.DELETE("/relationships/:relationship_id", app.HermesHandler.DeleteAppServiceRelationship)
			}
		}

		// 关系管理
		relationships := hermes.Group("/relationships")
		{
			relationships.GET("", app.HermesHandler.ListRelationships)
			relationships.POST("", app.HermesHandler.CreateRelationship)
			relationships.PATCH("", app.HermesHandler.UpdateRelationship)
			relationships.DELETE("", app.HermesHandler.DeleteRelationship)
		}

		// 组管理
		groups := hermes.Group("/groups")
		{
			groups.GET("", app.HermesHandler.ListGroups)
			groups.POST("", app.HermesHandler.CreateGroup)
			groups.GET("/:group_id", app.HermesHandler.GetGroup)
			groups.PATCH("/:group_id", app.HermesHandler.UpdateGroup)
			groups.GET("/:group_id/members", app.HermesHandler.GetGroupMembers)
			groups.POST("/:group_id/members", app.HermesHandler.SetGroupMembers)
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
