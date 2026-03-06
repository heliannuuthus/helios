package zwei

import (
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/pkg/aegis/web"
	"github.com/heliannuuthus/helios/pkg/aegis/web/guard"
	zweiconfig "github.com/heliannuuthus/helios/zwei/config"
	"github.com/heliannuuthus/helios/zwei/internal/favorite"
	"github.com/heliannuuthus/helios/zwei/internal/history"
	"github.com/heliannuuthus/helios/zwei/internal/home"
	"github.com/heliannuuthus/helios/zwei/internal/preference"
	"github.com/heliannuuthus/helios/zwei/internal/recipe"
	"github.com/heliannuuthus/helios/zwei/internal/recommend"
	"github.com/heliannuuthus/helios/zwei/internal/tag"
)

type Zwei struct {
	guard            *guard.GinGuard
	recipeHandler    *recipe.Handler
	favoriteHandler  *favorite.Handler
	historyHandler   *history.Handler
	homeHandler      *home.Handler
	tagHandler       *tag.Handler
	recommendHandler *recommend.Handler
	preferenceHandler *preference.Handler
}

func New(db *gorm.DB) *Zwei {
	g := guard.NewGinGuard(web.NewFactory().WithAudience(zweiconfig.GetAegisAudience()))

	return &Zwei{
		guard:            g,
		recipeHandler:    recipe.NewHandler(db),
		favoriteHandler:  favorite.NewHandler(db),
		historyHandler:   history.NewHandler(db),
		homeHandler:      home.NewHandler(db),
		tagHandler:       tag.NewHandler(db),
		recommendHandler: recommend.NewHandler(db),
		preferenceHandler: preference.NewHandler(db),
	}
}

func (z *Zwei) RegisterRoutes(r gin.IRouter) {
	api := r.Group("/api")

	recipes := api.Group("/recipes")
	{
		recipes.GET("", z.recipeHandler.GetRecipes)
		recipes.GET("/categories/list", z.recipeHandler.GetCategories)
		recipes.GET("/:recipe_id", z.recipeHandler.GetRecipe)
		recipes.POST("", z.guard.Require(web.Relation("admin")), z.recipeHandler.CreateRecipe)
		recipes.POST("/batch", z.guard.Require(web.Relation("admin")), z.recipeHandler.CreateRecipesBatch)
		recipes.PATCH("/:recipe_id", z.guard.Require(web.Relation("admin")), z.recipeHandler.UpdateRecipe)
		recipes.DELETE("/:recipe_id", z.guard.Require(web.Relation("admin")), z.recipeHandler.DeleteRecipe)
	}

	user := api.Group("/user")
	user.Use(z.guard.Require())
	{
		favorites := user.Group("/favorites")
		{
			favorites.GET("", z.favoriteHandler.GetFavorites)
			favorites.POST("", z.favoriteHandler.AddFavorite)
			favorites.POST("/batch-check", z.favoriteHandler.BatchCheckFavorites)
			favorites.GET("/:recipe_id/check", z.favoriteHandler.CheckFavorite)
			favorites.DELETE("/:recipe_id", z.favoriteHandler.RemoveFavorite)
		}

		historyGroup := user.Group("/history")
		{
			historyGroup.GET("", z.historyHandler.GetViewHistory)
			historyGroup.POST("", z.historyHandler.AddViewHistory)
			historyGroup.DELETE("", z.historyHandler.ClearViewHistory)
			historyGroup.DELETE("/:recipe_id", z.historyHandler.RemoveViewHistory)
		}

		preferenceGroup := user.Group("/preference")
		{
			preferenceGroup.GET("", z.preferenceHandler.GetUserPreferences)
			preferenceGroup.PUT("", z.preferenceHandler.UpdateUserPreferences)
		}
	}

	homeGroup := api.Group("/home")
	{
		homeGroup.GET("/banners", z.homeHandler.GetBanners)
		homeGroup.GET("/recommend", z.homeHandler.GetRecommendRecipes)
		homeGroup.GET("/hot", z.homeHandler.GetHotRecipes)
	}

	api.GET("/preferences", z.preferenceHandler.GetOptions)

	tags := api.Group("/tags")
	{
		tags.GET("", z.tagHandler.ListTags)
		tags.GET("/:type", z.tagHandler.GetTagsByType)
		tags.POST("", z.guard.Require(web.Relation("admin")), z.tagHandler.CreateTag)
		tags.PUT("/:type/:value", z.guard.Require(web.Relation("admin")), z.tagHandler.UpdateTag)
		tags.DELETE("/:type/:value", z.guard.Require(web.Relation("admin")), z.tagHandler.DeleteTag)
	}

	recommendGroup := api.Group("/recommend")
	{
		recommendGroup.POST("", z.recommendHandler.GetRecommendations)
		recommendGroup.POST("/context", z.guard.Require(), z.recommendHandler.GetContext)
	}
}
