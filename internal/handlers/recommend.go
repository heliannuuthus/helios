package handlers

import (
	"net/http"
	"strconv"
	"time"

	"choosy-backend/internal/auth"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/recommend"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RecommendHandler 推荐处理器
type RecommendHandler struct {
	service     *recommend.Service
	rateLimiter *recommend.DailyRateLimiter
}

// NewRecommendHandler 创建推荐处理器
func NewRecommendHandler(db *gorm.DB) *RecommendHandler {
	return &RecommendHandler{
		service:     recommend.NewService(db),
		rateLimiter: recommend.NewDailyRateLimiter(10), // 每日最多 10 次
	}
}

type RecommendRequest struct {
	Latitude   float64  `json:"latitude" binding:"required"`
	Longitude  float64  `json:"longitude" binding:"required"`
	Timestamp  int64    `json:"timestamp"`
	ExcludeIDs []string `json:"exclude_ids,omitempty"` // 排除的菜谱 ID（换一批时传入已推荐的）
}

// RecommendRecipeItem 推荐菜品项（包含推荐理由）
type RecommendRecipeItem struct {
	RecipeListItem
	Reason string `json:"reason"` // 该菜品的推荐理由
}

type RecommendResponse struct {
	Recipes   []RecommendRecipeItem `json:"recipes"`
	Summary   string                `json:"summary"`   // LLM 生成的一句话整体评价
	Remaining int                   `json:"remaining"` // 今日剩余推荐次数
}

// GetRecommendations 获取智能推荐
// @Summary 获取智能推荐菜谱
// @Description 根据地理位置、天气、时间等因素智能推荐菜谱（基于 LLM，支持用户个性化）
// @Tags recommend
// @Accept json
// @Produce json
// @Param request body RecommendRequest true "推荐请求"
// @Param limit query int false "返回数量" default(6)
// @Success 200 {object} RecommendResponse
// @Failure 400 {object} map[string]string
// @Router /api/recommend [post]
func (h *RecommendHandler) GetRecommendations(c *gin.Context) {
	var req RecommendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "缺少必要参数: latitude, longitude"})
		return
	}

	if req.Timestamp == 0 {
		req.Timestamp = time.Now().UnixMilli()
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "6"))
	if limit < 1 {
		limit = 1
	} else if limit > 20 {
		limit = 20
	}

	// 构建推荐上下文
	ctx := &recommend.Context{
		Latitude:   req.Latitude,
		Longitude:  req.Longitude,
		Timestamp:  req.Timestamp,
		ExcludeIDs: req.ExcludeIDs,
	}

	// 获取用户身份（如果已登录）
	if user, exists := c.Get("user"); exists {
		identity := user.(*auth.Identity)
		ctx.UserID = identity.GetOpenID()
	}

	// 检查每日推荐次数限制
	remaining, allowed := h.rateLimiter.Check(ctx.UserID)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"detail":    "今日推荐次数已用完，明天再来吧",
			"remaining": 0,
		})
		return
	}

	result, err := h.service.GetRecommendations(ctx, limit)
	if err != nil {
		logger.Errorf("[RecommendHandler] 获取推荐失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "服务器内部错误"})
		return
	}

	// 推荐成功，增加计数
	h.rateLimiter.Increment(ctx.UserID)

	response := RecommendResponse{
		Recipes:   make([]RecommendRecipeItem, len(result.Recipes)),
		Summary:   result.Summary,
		Remaining: remaining - 1, // 本次请求后的剩余次数
	}

	for i, r := range result.Recipes {
		response.Recipes[i] = RecommendRecipeItem{
			RecipeListItem: RecipeListItem{
				ID:               r.Recipe.RecipeID,
				Name:             r.Recipe.Name,
				Description:      r.Recipe.Description,
				Category:         r.Recipe.Category,
				Difficulty:       r.Recipe.Difficulty,
				Tags:             GroupTags(r.Recipe.Tags),
				ImagePath:        r.Recipe.GetImagePath(),
				TotalTimeMinutes: r.Recipe.TotalTimeMinutes,
			},
			Reason: r.Reason,
		}
	}

	c.JSON(http.StatusOK, response)
}
