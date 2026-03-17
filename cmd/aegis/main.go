package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/heliannuuthus/aegis-go/guard"
	"github.com/heliannuuthus/aegis-go/utilities/key"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/heliannuuthus/helios/aegis"
	aegisconfig "github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/hermesclient"
	"github.com/heliannuuthus/helios/aegis/middleware"
	_ "github.com/heliannuuthus/helios/docs"
	irisconfig "github.com/heliannuuthus/helios/iris/config"
	"github.com/heliannuuthus/helios/pkg/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

func main() {
	config.LoadConfig()
	config.LoadAegis()
	config.LoadIris()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()

	hermesAddr := os.Getenv("HERMES_GRPC_ADDR")
	if hermesAddr == "" {
		hermesAddr = "hermes:50051"
	}
	conn, err := grpc.NewClient(hermesAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Fatalf("连接 hermes gRPC 失败: %v", err)
	}
	defer conn.Close()

	client := hermesclient.New(conn)

	initTokenManager(client)

	aegisHandler, err := aegis.Initialize(client, client, client)
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
		authGroup.POST("/check", aegisHandler.Check)
	}

	profile := aegisHandler.Profile()
	irisGuard := guard.NewGin(irisconfig.GetAegisAudience())
	userGroup := r.Group("/user")
	{
		userRoutes := []struct {
			method, path string
			handler      gin.HandlerFunc
		}{
			{"GET", "/profile", profile.GetProfile},
			{"PATCH", "/profile", profile.UpdateProfile},
			{"POST", "/profile/avatar", profile.UploadAvatar},
			{"PUT", "/profile/email", profile.UpdateEmail},
			{"PUT", "/profile/phone", profile.UpdatePhone},
			{"GET", "/identities", profile.ListIdentities},
			{"POST", "/identities/:idp", profile.BindIdentity},
			{"DELETE", "/identities/:idp", profile.UnbindIdentity},
			{"GET", "/mfa", profile.GetMFAStatus},
			{"POST", "/mfa", profile.SetupMFA},
			{"PUT", "/mfa", profile.VerifyMFA},
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

func initTokenManager(client *hermesclient.Client) {
	endpoint := aegisconfig.GetIssuer()
	seed := key.SingleOf(func(_ context.Context, _ string) ([]byte, error) {
		keys, err := client.GetDomainKeys(context.Background(), "consumer")
		if err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("no domain keys found")
		}
		return keys[0], nil
	})
	guard.NewTokenManager(endpoint, seed)
}
