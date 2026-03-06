//go:build wireinject

package main

import (
	"github.com/google/wire"

	"github.com/heliannuuthus/helios/aegis"
	"github.com/heliannuuthus/helios/chaos"
	"github.com/heliannuuthus/helios/hermes"
	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/iris"
	"github.com/heliannuuthus/helios/zwei"
	zweiconfig "github.com/heliannuuthus/helios/zwei/config"
)

// ProviderSet 提供者集合
var ProviderSet = wire.NewSet(
	provideZwei,
	provideHermesService,
	provideHermesHandler,
	provideAegisHandler,
	provideIrisHandler,
	provideChaosHandler,
)

// App 应用依赖容器
type App struct {
	Zwei          *zwei.Zwei
	AegisHandler  *aegis.Handler
	IrisHandler   *iris.Handler
	HermesHandler *hermes.Handler
	ChaosHandler  *chaos.Handler
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}

// Zwei 业务模块
func provideZwei() *zwei.Zwei {
	return zwei.New(zweiconfig.InitDB())
}

// Hermes Service（供 aegis 模块复用）
func provideHermesService() *hermes.Service {
	return hermes.NewService(hermesconfig.InitDB())
}

// 认证模块 Handler（使用 Hermes 数据库，依赖 hermes.Service）
func provideAegisHandler(hermesService *hermes.Service) (*aegis.Handler, error) {
	db := hermesconfig.InitDB()
	userSvc := hermes.NewUserService(db)
	credentialSvc := hermes.NewCredentialService(db)
	return aegis.Initialize(hermesService, userSvc, credentialSvc)
}

func provideHermesHandler(hermesService *hermes.Service) *hermes.Handler {
	return hermes.NewHandler(hermesService)
}

// Iris 用户信息模块 Handler
func provideIrisHandler(aegisHandler *aegis.Handler) *iris.Handler {
	db := hermesconfig.InitDB()
	userSvc := hermes.NewUserService(db)
	credentialSvc := hermes.NewCredentialService(db)
	return iris.NewHandler(userSvc, credentialSvc, aegisHandler.MFASvc())
}

// Chaos 业务聚合模块
func provideChaosHandler() (*chaos.Handler, error) {
	db := hermesconfig.InitDB()
	chaosModule, err := chaos.New(db)
	if err != nil {
		return nil, err
	}
	return chaosModule.Handler(), nil
}
