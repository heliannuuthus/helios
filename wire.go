//go:build wireinject
// +build wireinject

package main

import (
	"github.com/google/wire"

	"github.com/heliannuuthus/helios/internal/auth"
	"github.com/heliannuuthus/helios/internal/database"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/upload"
	"github.com/heliannuuthus/helios/internal/zwei/favorite"
	"github.com/heliannuuthus/helios/internal/zwei/history"
	"github.com/heliannuuthus/helios/internal/zwei/home"
	"github.com/heliannuuthus/helios/internal/zwei/preference"
	"github.com/heliannuuthus/helios/internal/zwei/recipe"
	"github.com/heliannuuthus/helios/internal/zwei/recommend"
	"github.com/heliannuuthus/helios/internal/zwei/tag"
)

// 业务模块 Handler（使用 Zwei 数据库）
func provideRecipeHandler() *recipe.Handler {
	return recipe.NewHandler(database.GetZwei())
}

func provideFavoriteHandler() *favorite.Handler {
	return favorite.NewHandler(database.GetZwei())
}

func provideHistoryHandler() *history.Handler {
	return history.NewHandler(database.GetZwei())
}

func providePreferenceHandler() *preference.Handler {
	return preference.NewHandler(database.GetZwei())
}

func provideTagHandler() *tag.Handler {
	return tag.NewHandler(database.GetZwei())
}

func provideRecommendHandler() *recommend.Handler {
	return recommend.NewHandler(database.GetZwei())
}

func provideHomeHandler() *home.Handler {
	return home.NewHandler(database.GetZwei())
}

// Hermes Service（供 auth 模块复用）
func provideHermesService() *hermes.Service {
	return hermes.NewService()
}

// 认证模块 Handler（使用 Hermes 数据库，依赖 hermes.Service）
func provideAuthHandler(hermesService *hermes.Service) (*auth.Handler, error) {
	userSvc := hermes.NewUserService(database.GetHermes())
	return auth.Initialize(&auth.InitConfig{
		HermesSvc: hermesService,
		UserSvc:   userSvc,
	})
}

func provideUploadHandler() *upload.Handler {
	return upload.NewHandler(database.GetHermes())
}

func provideHermesHandler(hermesService *hermes.Service) *hermes.Handler {
	return hermes.NewHandler(hermesService)
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
	// Hermes 模块（使用 Hermes 数据库，提供给 auth 复用）
	provideHermesService,
	provideHermesHandler,
	// 认证模块（使用 Hermes 数据库，依赖 hermes.Service）
	provideAuthHandler,
	provideUploadHandler,
)

// App 应用依赖容器
type App struct {
	RecipeHandler     *recipe.Handler
	AuthHandler       *auth.Handler
	FavoriteHandler   *favorite.Handler
	HistoryHandler    *history.Handler
	HomeHandler       *home.Handler
	TagHandler        *tag.Handler
	RecommendHandler  *recommend.Handler
	UploadHandler     *upload.Handler
	PreferenceHandler *preference.Handler
	HermesHandler     *hermes.Handler
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
