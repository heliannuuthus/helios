package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	aegisconfig "github.com/heliannuuthus/aegis/config"
	"github.com/heliannuuthus/aegis/internal/cache"
	"github.com/heliannuuthus/aegis/middleware"
	"github.com/heliannuuthus/aegis/models"
	hermesrpc "github.com/heliannuuthus/aegis/rpc/hermes"
	"github.com/heliannuuthus/pkg/aegis/guard"
	"github.com/heliannuuthus/pkg/aegis/utilities/key"
	"github.com/heliannuuthus/pkg/config"
	"github.com/heliannuuthus/pkg/logger"
	pkgredis "github.com/heliannuuthus/pkg/redis"
)

func main() {
	config.LoadAegis()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()
	if err := aegisconfig.Validate(); err != nil {
		logger.Fatalf("Aegis 配置校验失败: %v", err)
	}

	hermesAddr := os.Getenv("HERMES_GRPC_ADDR")
	if hermesAddr == "" {
		hermesAddr = "hermes:50051"
	}
	conn, err := grpc.NewClient(hermesAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Fatalf("连接 hermes gRPC 失败: %v", err)
	}
	defer conn.Close()

	client := hermesrpc.New(conn)

	if err := initTokenManager(client); err != nil {
		logger.Fatalf("初始化 Aegis token manager 失败: %v", err)
	}

	redisURL := aegisconfig.Cfg().GetString("redis.url")
	if redisURL == "" {
		redisURL = "redis://localhost:6379/0"
	}
	redis, err := pkgredis.NewClient(redisURL)
	if err != nil {
		logger.Fatalf("连接 Redis 失败: %v", err)
	}
	logger.Infof("[Auth] Redis 连接成功")

	cacheManager := cache.NewManager(client, redis)
	aegisHandler, err := initializeAegis(client, cacheManager)
	if err != nil {
		logger.Fatalf("初始化 aegis 失败: %v", err)
	}

	if !config.IsDebug() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()
	r.RedirectTrailingSlash = false

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	aegisCORS := middleware.CORS(aegisHandler.CacheManager())

	authGroup := r.Group("/auth")
	{
		corsRoutes := []struct {
			method, path string
			handler      gin.HandlerFunc
		}{
			{"POST", "/authorize", aegisHandler.Authorize},
			{"GET", "/connections", aegisHandler.GetConnections},
			{"GET", "/context", aegisHandler.GetContext},
			{"POST", "/login", aegisHandler.Login},
			{"POST", "/idps", aegisHandler.IDPs},
			{"GET", "/binding", aegisHandler.GetIdentifyContext},
			{"POST", "/binding", aegisHandler.ConfirmIdentify},
			{"POST", "/challenge", aegisHandler.InitiateChallenge},
			{"POST", "/challenge/:cid", aegisHandler.ContinueChallenge},
			{"POST", "/token", aegisHandler.Token},
			{"POST", "/revoke", aegisHandler.Revoke},
			{"POST", "/logout", aegisHandler.Logout},
			{"GET", "/logout", aegisHandler.LogoutGET},
			{"GET", "/pubkeys", aegisHandler.PublicKeys},
		}
		registered := make(map[string]bool)
		for _, route := range corsRoutes {
			authGroup.Handle(route.method, route.path, aegisCORS, route.handler)
			if !registered[route.path] {
				authGroup.OPTIONS(route.path, aegisCORS)
				registered[route.path] = true
			}
		}
		authGroup.GET("/idps/:connection/callback", aegisHandler.OAuthCallback)
		authGroup.POST("/check", aegisHandler.Check)
	}

	profile := aegisHandler.Profile()
	irisGuard, err := guard.NewGin(aegisconfig.GetIrisAudience())
	if err != nil {
		logger.Fatalf("初始化 Iris 鉴权中间件失败: %v", err)
	}
	userGroup := r.Group("/user")
	{
		userRoutes := []struct {
			method, path string
			handler      gin.HandlerFunc
		}{
			{"GET", "/profile", profile.GetProfile},
			{"PATCH", "/profile", profile.UpdateProfile},
			{"GET", "/identities", profile.ListIdentities},
			{"POST", "/identities/:idp", profile.BindIdentity},
			{"DELETE", "/identities/:idp", profile.UnbindIdentity},
			{"GET", "/mfa", profile.GetMFAStatus},
			{"POST", "/mfa", profile.SetupMFA},
			{"POST", "/mfa/:uid", profile.CompleteMFA},
			{"PATCH", "/mfa", profile.UpdateMFA},
			{"DELETE", "/mfa", profile.DeleteMFA},
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

	addr := fmt.Sprintf(":%d", config.GetServerPort())
	logger.Infof("aegis 服务启动: %s", addr)
	if err := r.Run(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}

func initTokenManager(client *hermesrpc.Client) error {
	endpoint := aegisconfig.GetIssuer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keys, err := client.GetKeys(ctx, models.KeyOwnerDomain, "consumer")
	if err != nil {
		return fmt.Errorf("预加载 consumer 域密钥: %w", err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("consumer 域密钥不存在")
	}
	if len(keys[0]) != 48 {
		return fmt.Errorf("consumer 域密钥长度错误: 期望 48 字节, 实际 %d 字节", len(keys[0]))
	}
	seed := key.SingleOf(func(_ context.Context, _ string) ([]byte, error) {
		keys, err := client.GetKeys(context.Background(), models.KeyOwnerDomain, "consumer")
		if err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("no domain keys found")
		}
		return keys[0], nil
	})
	guard.NewTokenManager(endpoint, seed)
	return nil
}
