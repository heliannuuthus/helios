//go:build wireinject

package main

import (
	"github.com/google/wire"

	"github.com/heliannuuthus/helios/aegis"
	aegisconfig "github.com/heliannuuthus/helios/aegis/config"
	intMw "github.com/heliannuuthus/helios/aegis/middleware"
	"github.com/heliannuuthus/helios/chaos"
	"github.com/heliannuuthus/helios/hermes"
	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/iris"
	"github.com/heliannuuthus/helios/pkg/aegis/middleware"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	zweiconfig "github.com/heliannuuthus/helios/zwei/config"
	"github.com/heliannuuthus/helios/zwei/favorite"
	"github.com/heliannuuthus/helios/zwei/history"
	"github.com/heliannuuthus/helios/zwei/home"
	"github.com/heliannuuthus/helios/zwei/preference"
	"github.com/heliannuuthus/helios/zwei/recipe"
	"github.com/heliannuuthus/helios/zwei/recommend"
	"github.com/heliannuuthus/helios/zwei/tag"
)

// 业务模块 Handler（使用 Zwei 数据库）
func provideRecipeHandler() *recipe.Handler {
	return recipe.NewHandler(zweiconfig.InitDB())
}

func provideFavoriteHandler() *favorite.Handler {
	return favorite.NewHandler(zweiconfig.InitDB())
}

func provideHistoryHandler() *history.Handler {
	return history.NewHandler(zweiconfig.InitDB())
}

func providePreferenceHandler() *preference.Handler {
	return preference.NewHandler(zweiconfig.InitDB())
}

func provideTagHandler() *tag.Handler {
	return tag.NewHandler(zweiconfig.InitDB())
}

func provideRecommendHandler() *recommend.Handler {
	return recommend.NewHandler(zweiconfig.InitDB())
}

func provideHomeHandler() *home.Handler {
	return home.NewHandler(zweiconfig.InitDB())
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

// provideInterpreter 创建 Token 解释器（用于 API 路由认证中间件）
func provideInterpreter() (*token.Interpreter, error) {
	keyStore, err := intMw.NewHermesKeyStore()
	if err != nil {
		return nil, err
	}

	return token.NewInterpreter(keyStore, keyStore), nil
}

// provideGinMiddlewareFactory 创建 Gin 中间件工厂
func provideGinMiddlewareFactory() (*middleware.GinFactory, error) {
	endpoint := aegisconfig.GetIssuer()

	keyStore, err := intMw.NewHermesKeyStore()
	if err != nil {
		return nil, err
	}

	return middleware.NewGinFactory(
		endpoint,
		keyStore, // 签名验证
		keyStore, // footer 解密
		keyStore, // CAT 签发
	), nil
}

// ProviderSet 提供者集合
var ProviderSet = wire.NewSet(
	// 业务模块（使用 Zwei 数据库）
	recipe.NewService,
	favorite.NewService,
	history.NewService,
	preference.NewService,
	tag.NewService,
	recommend.NewService,
	provideRecipeHandler,
	provideFavoriteHandler,
	provideHistoryHandler,
	providePreferenceHandler,
	provideTagHandler,
	provideRecommendHandler,
	provideHomeHandler,
	// Hermes 模块（使用 Hermes 数据库，提供给 aegis 复用）
	provideHermesService,
	provideHermesHandler,
	// 认证模块（使用 Hermes 数据库，依赖 hermes.Service）
	provideAegisHandler,
	// Iris 用户信息模块
	provideIrisHandler,
	// Chaos 业务聚合模块
	provideChaosHandler,
	// 中间件
	provideInterpreter,
	provideGinMiddlewareFactory,
)

// App 应用依赖容器
type App struct {
	RecipeHandler     *recipe.Handler
	AegisHandler      *aegis.Handler
	IrisHandler       *iris.Handler
	FavoriteHandler   *favorite.Handler
	HistoryHandler    *history.Handler
	HomeHandler       *home.Handler
	TagHandler        *tag.Handler
	RecommendHandler  *recommend.Handler
	PreferenceHandler *preference.Handler
	HermesHandler     *hermes.Handler
	ChaosHandler      *chaos.Handler
	MiddlewareFactory *middleware.GinFactory
	Interpreter       *token.Interpreter
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
