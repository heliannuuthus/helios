//go:build wireinject
// +build wireinject

package main

import (
	"github.com/heliannuuthus/helios/internal/auth"
	"github.com/heliannuuthus/helios/internal/database"
	"github.com/heliannuuthus/helios/internal/management/upload"
	"github.com/heliannuuthus/helios/internal/zwei/favorite"
	"github.com/heliannuuthus/helios/internal/zwei/history"
	"github.com/heliannuuthus/helios/internal/zwei/home"
	"github.com/heliannuuthus/helios/internal/zwei/preference"
	"github.com/heliannuuthus/helios/internal/zwei/recipe"
	"github.com/heliannuuthus/helios/internal/zwei/recommend"
	"github.com/heliannuuthus/helios/internal/zwei/tag"

	"github.com/google/wire"
	"gorm.io/gorm"
)

// 包装函数：明确指定数据库连接

// provideZweiDB 提供 Zwei 业务数据库连接
func provideZweiDB() *gorm.DB {
	return database.GetZwei()
}

// provideAuthDB 提供 Auth 认证数据库连接
func provideAuthDB() *gorm.DB {
	return database.GetAuth()
}

// 业务模块 Handler（使用 Zwei 数据库）
func provideRecipeHandler(zweiDB *gorm.DB) *recipe.Handler {
	return recipe.NewHandler(zweiDB)
}

func provideFavoriteHandler(zweiDB *gorm.DB) *favorite.Handler {
	return favorite.NewHandler(zweiDB)
}

func provideHistoryHandler(zweiDB *gorm.DB) *history.Handler {
	return history.NewHandler(zweiDB)
}

func providePreferenceHandler(zweiDB *gorm.DB) *preference.Handler {
	return preference.NewHandler(zweiDB)
}

func provideTagHandler(zweiDB *gorm.DB) *tag.Handler {
	return tag.NewHandler(zweiDB)
}

func provideRecommendHandler(zweiDB *gorm.DB) *recommend.Handler {
	return recommend.NewHandler(zweiDB)
}

func provideHomeHandler(zweiDB *gorm.DB) *home.Handler {
	return home.NewHandler(zweiDB)
}

// 认证模块 Handler（使用 Auth 数据库）
func provideAuthHandler(authDB *gorm.DB) (*auth.Handler, error) {
	authService, err := auth.NewService(authDB)
	if err != nil {
		return nil, err
	}
	return auth.NewHandler(authService), nil
}

func provideUploadHandler(authDB *gorm.DB) *upload.Handler {
	return upload.NewHandler(authDB)
}

// ProviderSet 提供者集合
var ProviderSet = wire.NewSet(
	provideZweiDB,
	provideAuthDB,
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
	// 认证模块（使用 Auth 数据库）
	provideAuthHandler,
	provideUploadHandler,
)

// App 应用依赖容器
type App struct {
	DB                *gorm.DB
	RecipeHandler     *recipe.Handler
	AuthHandler       *auth.Handler
	FavoriteHandler   *favorite.Handler
	HistoryHandler    *history.Handler
	HomeHandler       *home.Handler
	TagHandler        *tag.Handler
	RecommendHandler  *recommend.Handler
	UploadHandler     *upload.Handler
	PreferenceHandler *preference.Handler
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
