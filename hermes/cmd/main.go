package main

import (
	"context"
	"fmt"
	"net"

	"github.com/gin-gonic/gin"
	"github.com/heliannuuthus/aegis-go/guard"
	reqr "github.com/heliannuuthus/aegis-go/guard/requirement"
	"github.com/heliannuuthus/aegis-go/utilities/relation"
	"google.golang.org/grpc"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	hermesgrpc "github.com/heliannuuthus/helios/hermes/grpc"
	"github.com/heliannuuthus/helios/pkg/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

func main() {
	config.LoadConfig()
	config.LoadHermes()
	logger.InitWithConfig(logger.Config{
		Format: config.GetLogFormat(),
		Level:  config.GetLogLevel(),
		Debug:  config.IsDebug(),
	})
	defer logger.Sync()

	db := hermesconfig.InitDB()

	svc := hermes.NewService(db)

	go startGRPC(svc)
	startHTTP(svc)
}

func startGRPC(svc *hermes.Service) {
	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", ":50051")
	if err != nil {
		logger.Fatalf("gRPC listen 失败: %v", err)
	}

	s := grpc.NewServer()
	hermesv1.RegisterProvisionServiceServer(s, hermesgrpc.NewProvisionServiceServer(svc))
	hermesv1.RegisterResourceServiceServer(s, hermesgrpc.NewResourceServiceServer(svc))
	hermesv1.RegisterKeyServiceServer(s, hermesgrpc.NewKeyServiceServer(svc))
	hermesv1.RegisterUserServiceServer(s, hermesgrpc.NewUserServiceServer(svc))

	logger.Infof("hermes gRPC 服务启动: :50051")
	if err := s.Serve(lis); err != nil {
		logger.Fatalf("gRPC serve 失败: %v", err)
	}
}

func startHTTP(svc *hermes.Service) {
	if !config.IsDebug() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()
	r.RedirectTrailingSlash = false

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	handler := hermes.NewHandler(svc)

	hermesAud := hermesconfig.GetAegisAudience()
	hermesGuard := guard.NewGin(hermesAud)
	adminRelation := hermesGuard.Require(reqr.Relation(relation.Qualify("admin", "service:"+hermesAud)))
	api := r.Group("/hermes")
	api.Use(hermesGuard.Require())
	{
		domains := api.Group("/domains")
		{
			domains.GET("", handler.ListDomains)
			domains.GET("/:domain_id", handler.GetDomain)
			domains.PATCH("/:domain_id", adminRelation, handler.UpdateDomain)
			domains.DELETE("/:domain_id", adminRelation, handler.DeleteDomain)

			domainIDPConfigs := domains.Group("/:domain_id/idp-configs")
			{
				domainIDPConfigs.GET("", handler.ListDomainIDPConfigs)
				domainIDPConfigs.GET("/:idp_type", handler.GetDomainIDPConfig)
				domainIDPConfigs.POST("", adminRelation, handler.CreateDomainIDPConfig)
				domainIDPConfigs.PATCH("/:idp_type", adminRelation, handler.UpdateDomainIDPConfig)
				domainIDPConfigs.DELETE("/:idp_type", adminRelation, handler.DeleteDomainIDPConfig)
			}

			domainServices := domains.Group("/:domain_id/services")
			{
				domainServices.GET("", handler.ListServices)
				domainServices.GET("/:service_id", handler.GetService)
				domainServices.GET("/:service_id/applications", handler.GetServiceApplicationRelations)
				domainServices.GET("/:service_id/applications/:app_id/relations", handler.GetServiceAppRelations)
				domainServices.PUT("/:service_id/applications/:app_id/relations", adminRelation, handler.SetServiceAppRelations)
				domainServices.POST("", adminRelation, handler.CreateService)
				domainServices.PATCH("/:service_id", adminRelation, handler.UpdateService)
				domainServices.DELETE("/:service_id", adminRelation, handler.DeleteService)

				challengeSettings := domainServices.Group("/:service_id/challenge-settings")
				{
					challengeSettings.GET("", handler.ListServiceChallengeSettings)
					challengeSettings.POST("", adminRelation, handler.CreateServiceChallengeSetting)
					challengeSettings.PATCH("/:type", adminRelation, handler.UpdateServiceChallengeSetting)
					challengeSettings.DELETE("/:type", adminRelation, handler.DeleteServiceChallengeSetting)
				}
			}

			domainApps := domains.Group("/:domain_id/applications")
			{
				domainApps.GET("", handler.ListApplications)
				domainApps.GET("/:app_id", handler.GetApplication)
				domainApps.GET("/:app_id/relations", handler.GetApplicationServiceRelations)
				domainApps.GET("/:app_id/idp-configs", handler.ListApplicationIDPConfigs)
				domainApps.POST("", adminRelation, handler.CreateApplication)
				domainApps.PATCH("/:app_id", adminRelation, handler.UpdateApplication)
				domainApps.DELETE("/:app_id", adminRelation, handler.DeleteApplication)
				domainApps.POST("/:app_id/idp-configs", adminRelation, handler.CreateApplicationIDPConfig)
				domainApps.PATCH("/:app_id/idp-configs/:idp_type", adminRelation, handler.UpdateApplicationIDPConfig)
				domainApps.DELETE("/:app_id/idp-configs/:idp_type", adminRelation, handler.DeleteApplicationIDPConfig)

				appServices := domainApps.Group("/:app_id/services/:service_id")
				{
					appServices.GET("/relationships", handler.ListAppServiceRelationships)
					appServices.POST("/relationships", adminRelation, handler.CreateAppServiceRelationship)
					appServices.PATCH("/relationships/:relationship_id", adminRelation, handler.UpdateAppServiceRelationship)
					appServices.DELETE("/relationships/:relationship_id", adminRelation, handler.DeleteAppServiceRelationship)
				}
			}
		}

		relationships := api.Group("/relationships")
		{
			relationships.GET("", handler.ListRelationships)
			relationships.POST("", adminRelation, handler.CreateRelationship)
			relationships.PATCH("", adminRelation, handler.UpdateRelationship)
			relationships.DELETE("", adminRelation, handler.DeleteRelationship)
		}

		groups := api.Group("/groups")
		{
			groups.GET("", handler.ListGroups)
			groups.GET("/:group_id", handler.GetGroup)
			groups.GET("/:group_id/members", handler.GetGroupMembers)
			groups.POST("", adminRelation, handler.CreateGroup)
			groups.PATCH("/:group_id", adminRelation, handler.UpdateGroup)
			groups.DELETE("/:group_id", adminRelation, handler.DeleteGroup)
			groups.POST("/:group_id/members", adminRelation, handler.SetGroupMembers)
		}

		idpKeys := api.Group("/idp-keys")
		{
			idpKeys.GET("", handler.ListIDPKeys)
			idpKeys.GET("/:idp_type/:t_app_id", handler.GetIDPKey)
			idpKeys.POST("", adminRelation, handler.CreateIDPKey)
			idpKeys.PATCH("/:idp_type/:t_app_id", adminRelation, handler.UpdateIDPKey)
			idpKeys.DELETE("/:idp_type/:t_app_id", adminRelation, handler.DeleteIDPKey)
		}
	}

	addr := fmt.Sprintf(":%d", config.GetServerPort())
	logger.Infof("hermes HTTP 服务启动: %s", addr)
	if err := r.Run(addr); err != nil {
		logger.Fatalf("HTTP 服务启动失败: %v", err)
	}
}
