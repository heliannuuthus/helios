package zwei

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/heliannuuthus/pkg/aegis/guard"
	reqr "github.com/heliannuuthus/pkg/aegis/guard/requirement"
	"github.com/heliannuuthus/pkg/aegis/utilities/relation"
	zweiconfig "github.com/heliannuuthus/zwei/config"
	"github.com/heliannuuthus/zwei/internal/favorite"
	"github.com/heliannuuthus/zwei/internal/history"
	"github.com/heliannuuthus/zwei/internal/home"
	"github.com/heliannuuthus/zwei/internal/preference"
	"github.com/heliannuuthus/zwei/internal/recipe"
	"github.com/heliannuuthus/zwei/internal/recommend"
	"github.com/heliannuuthus/zwei/internal/tag"
)

type Zwei struct {
	guard             *guard.Gin
	recipeHandler     *recipe.Handler
	favoriteHandler   *favorite.Handler
	historyHandler    *history.Handler
	homeHandler       *home.Handler
	tagHandler        *tag.Handler
	recommendHandler  *recommend.Handler
	preferenceHandler *preference.Handler
}

func New(db *gorm.DB) (*Zwei, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库连接未初始化")
	}
	g, err := guard.NewGin(zweiconfig.GetAegisAudience())
	if err != nil {
		return nil, fmt.Errorf("创建鉴权中间件失败: %w", err)
	}
	if err := tag.InitializeCache(); err != nil {
		return nil, fmt.Errorf("初始化标签缓存失败: %w", err)
	}
	recipeHandler, err := recipe.NewHandler(db)
	if err != nil {
		return nil, fmt.Errorf("创建菜谱服务失败: %w", err)
	}
	homeHandler, err := home.NewHandler(db)
	if err != nil {
		return nil, fmt.Errorf("创建首页服务失败: %w", err)
	}
	recommendHandler, err := recommend.NewHandler(db)
	if err != nil {
		return nil, fmt.Errorf("创建推荐服务失败: %w", err)
	}

	return &Zwei{
		guard:             g,
		recipeHandler:     recipeHandler,
		favoriteHandler:   favorite.NewHandler(db),
		historyHandler:    history.NewHandler(db),
		homeHandler:       homeHandler,
		tagHandler:        tag.NewHandler(db),
		recommendHandler:  recommendHandler,
		preferenceHandler: preference.NewHandler(db),
	}, nil
}

func (z *Zwei) RegisterRoutes(r gin.IRouter) {
	aud := zweiconfig.GetAegisAudience()
	adminReqr := z.guard.Require(reqr.Relation(relation.Qualify("admin", "service:"+aud)))

	zwei := r.Group("/zwei")

	recipes := zwei.Group("/recipes")
	{
		recipes.GET("", z.recipeHandler.GetRecipes)
		recipes.GET("/categories/list", z.recipeHandler.GetCategories)
		recipes.GET("/:recipe_id", z.recipeHandler.GetRecipe)
		recipes.POST("", adminReqr, z.recipeHandler.CreateRecipe)
		recipes.POST("/batch", adminReqr, z.recipeHandler.CreateRecipesBatch)
		recipes.PATCH("/:recipe_id", adminReqr, z.recipeHandler.UpdateRecipe)
		recipes.DELETE("/:recipe_id", adminReqr, z.recipeHandler.DeleteRecipe)
	}

	user := zwei.Group("/user")
	user.Use(z.guard.Require(reqr.User()))
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

	homeGroup := zwei.Group("/home")
	{
		homeGroup.GET("/banners", z.homeHandler.GetBanners)
		homeGroup.GET("/recommend", z.homeHandler.GetRecommendRecipes)
		homeGroup.GET("/hot", z.homeHandler.GetHotRecipes)
	}

	zwei.GET("/preferences", z.preferenceHandler.GetOptions)

	tags := zwei.Group("/tags")
	{
		tags.GET("", z.tagHandler.ListTags)
		tags.GET("/:type", z.tagHandler.GetTagsByType)
		tags.POST("", adminReqr, z.tagHandler.CreateTag)
		tags.PUT("/:type/:value", adminReqr, z.tagHandler.UpdateTag)
		tags.DELETE("/:type/:value", adminReqr, z.tagHandler.DeleteTag)
	}

	recommendGroup := zwei.Group("/recommend")
	{
		recommendGroup.POST("", z.recommendHandler.GetRecommendations)
		recommendGroup.POST("/context", z.guard.Require(reqr.User()), z.recommendHandler.GetContext)
	}
}
