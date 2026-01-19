//go:build wireinject
// +build wireinject

package main

import (
	"github.com/heliannuuthus/helios/internal/auth"
	"github.com/heliannuuthus/helios/internal/database"
	"github.com/heliannuuthus/helios/internal/favorite"
	"github.com/heliannuuthus/helios/internal/history"
	"github.com/heliannuuthus/helios/internal/home"
	"github.com/heliannuuthus/helios/internal/preference"
	"github.com/heliannuuthus/helios/internal/recipe"
	"github.com/heliannuuthus/helios/internal/recommend"
	"github.com/heliannuuthus/helios/internal/tag"
	"github.com/heliannuuthus/helios/internal/upload"
	"github.com/heliannuuthus/helios/internal/zwei"

	"github.com/google/wire"
	"gorm.io/gorm"
)

// ProviderSet 提供者集合
var ProviderSet = wire.NewSet(
	database.Get,
	recipe.NewService,
	auth.NewService,
	favorite.NewService,
	history.NewService,
	preference.NewService,
	tag.NewService,
	recommend.NewService,
	zwei.NewService,
	recipe.NewHandler,
	auth.NewHandler,
	favorite.NewHandler,
	history.NewHandler,
	home.NewHandler,
	tag.NewHandler,
	recommend.NewHandler,
	upload.NewHandler,
	preference.NewHandler,
	zwei.NewHandler,
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
	ZweiHandler       *zwei.Handler
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
