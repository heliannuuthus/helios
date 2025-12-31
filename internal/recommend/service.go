package recommend

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"choosy-backend/internal/amap"
	"choosy-backend/internal/config"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/models"
	"choosy-backend/internal/utils"

	"github.com/sashabaranov/go-openai"
	"gorm.io/gorm"
)

// Service 推荐服务
type Service struct {
	db         *gorm.DB
	amap       *amap.Client
	llmClient  *openai.Client
}

// WeatherInfo 天气信息
type WeatherInfo struct {
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
	Weather     string  `json:"weather"`
	City        string  `json:"city"`
}

// Context 推荐上下文
type Context struct {
	UserID    string  `json:"user_id,omitempty"` // 新增：用户 ID
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timestamp int64   `json:"timestamp"`
}

// Result 推荐结果
type Result struct {
	Recipes     []models.Recipe `json:"recipes"`
	Reason      string          `json:"reason"`
	Weather     *WeatherInfo    `json:"weather"`
	MealTime    string          `json:"meal_time"`
	Season      string          `json:"season"`
	Temperature string          `json:"temperature"`
}

// UserHistory 用户历史
type UserHistory struct {
	FavoriteRecipes []RecipeInfo `json:"favorite_recipes"`
	ViewedRecipes   []RecipeInfo `json:"viewed_recipes"`
	RecentDislikes  []string     `json:"recent_dislikes"`
}

// RecipeInfo 菜谱基本信息
type RecipeInfo struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`
	Description string   `json:"description,omitempty"`
}

// LLMRecommendation LLM 推荐结果
type LLMRecommendation struct {
	RecipeIDs []string `json:"recipe_ids"` // 推荐的菜谱 ID
	Reason    string   `json:"reason"`     // 推荐理由
}

// NewService 创建推荐服务
func NewService(db *gorm.DB) *Service {
	// 配置 OpenRouter 客户端
	apiKey := config.GetString("openrouter.api_key")
	clientConfig := openai.DefaultConfig(apiKey)
	clientConfig.BaseURL = "https://openrouter.ai/api/v1"
	
	return &Service{
		db:        db,
		amap:      amap.GetClient(),
		llmClient: openai.NewClientWithConfig(clientConfig),
	}
}

// GetRecommendations 获取推荐菜谱（基于 LLM）
func (s *Service) GetRecommendations(ctx *Context, limit int) (*Result, error) {
	result := &Result{}

	// 1. 获取天气信息
	weather, err := s.amap.GetWeather(ctx.Latitude, ctx.Longitude)
	if err != nil {
		logger.Warnf("获取天气失败，使用默认值: %v", err)
		weather = &amap.Weather{Temperature: 20, Weather: "晴"}
	}
	result.Weather = &WeatherInfo{
		Temperature: weather.Temperature,
		Humidity:    weather.Humidity,
		Weather:     weather.Weather,
	}

	// 2. 提取上下文特征
	t := time.UnixMilli(ctx.Timestamp)
	result.MealTime = utils.GetMealTime(t)
	result.Season = utils.GetSeason(t)
	result.Temperature = getTemperatureFeeling(weather.Temperature)

	// 3. 获取用户历史（如果有用户 ID）
	var userHistory *UserHistory
	if ctx.UserID != "" {
		userHistory, err = s.getUserHistory(ctx.UserID)
		if err != nil {
			logger.Warnf("获取用户历史失败: %v", err)
		}
	}

	// 4. 使用 LLM 生成推荐
	llmResult, err := s.getLLMRecommendations(result, userHistory, limit)
	if err != nil {
		logger.Errorf("LLM 推荐失败: %v", err)
		// 降级：返回随机菜谱
		return s.getFallbackRecommendations(result, limit)
	}

	// 5. 查询推荐的菜谱
	recipes, err := s.queryRecipesByIDs(llmResult.RecipeIDs)
	if err != nil {
		logger.Errorf("查询菜谱失败: %v", err)
		return s.getFallbackRecommendations(result, limit)
	}

	// 6. 填充标签信息
	if err := s.fillTags(recipes); err != nil {
		logger.Warnf("填充标签失败: %v", err)
	}

	result.Recipes = recipes
	result.Reason = llmResult.Reason

	logger.Infof("[Recommend] LLM 推荐成功 - UserID: %s, 推荐数量: %d", ctx.UserID, len(recipes))

	return result, nil
}

// getUserHistory 获取用户历史
func (s *Service) getUserHistory(userID string) (*UserHistory, error) {
	history := &UserHistory{
		FavoriteRecipes: []RecipeInfo{},
		ViewedRecipes:   []RecipeInfo{},
		RecentDislikes:  []string{},
	}

	// 获取收藏的菜谱（最近30个）
	var favorites []models.Favorite
	err := s.db.Where("openid = ?", userID).
		Order("created_at DESC").
		Limit(30).
		Find(&favorites).Error
	if err != nil {
		return nil, err
	}

	if len(favorites) > 0 {
		favoriteIDs := make([]string, len(favorites))
		for i, f := range favorites {
			favoriteIDs[i] = f.RecipeID
		}

		var recipes []models.Recipe
		s.db.Where("recipe_id IN ?", favoriteIDs).Find(&recipes)
		
		// 填充标签
		s.fillTags(recipes)

		for _, r := range recipes {
			tags := make([]string, len(r.Tags))
			for i, t := range r.Tags {
				tags[i] = t.Value
			}
			desc := ""
			if r.Description != nil {
				desc = *r.Description
			}
			history.FavoriteRecipes = append(history.FavoriteRecipes, RecipeInfo{
				Name:        r.Name,
				Category:    r.Category,
				Tags:        tags,
				Description: desc,
			})
		}
	}

	// TODO: 如果有浏览历史表，也可以添加
	// TODO: 如果有"不感兴趣"功能，也可以添加

	return history, nil
}

// getLLMRecommendations 使用 LLM 生成推荐
func (s *Service) getLLMRecommendations(result *Result, userHistory *UserHistory, limit int) (*LLMRecommendation, error) {
	// 1. 获取候选菜谱池（所有菜谱）
	var allRecipes []models.Recipe
	err := s.db.Select("recipe_id, name, category, description, difficulty").
		Limit(500). // 限制候选数量以控制 token 消耗
		Find(&allRecipes).Error
	if err != nil {
		return nil, err
	}

	// 填充标签
	s.fillTags(allRecipes)

	// 2. 构建候选菜谱列表（JSON 格式）
	type CandidateRecipe struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Category    string   `json:"category"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
		Difficulty  int      `json:"difficulty"`
	}

	candidates := make([]CandidateRecipe, len(allRecipes))
	for i, r := range allRecipes {
		tags := make([]string, len(r.Tags))
		for j, t := range r.Tags {
			tags[j] = t.Value
		}
		desc := ""
		if r.Description != nil {
			desc = *r.Description
		}
		candidates[i] = CandidateRecipe{
			ID:          r.RecipeID,
			Name:        r.Name,
			Category:    r.Category,
			Tags:        tags,
			Description: desc,
			Difficulty:  r.Difficulty,
		}
	}

	candidatesJSON, _ := json.MarshalIndent(candidates, "", "  ")

	// 3. 构建 Prompt
	prompt := s.buildRecommendPrompt(result, userHistory, string(candidatesJSON), limit)

	// 4. 调用 LLM
	logger.Infof("[Recommend] 调用 LLM - Prompt 长度: %d", len(prompt))

	resp, err := s.llmClient.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: "google/gemini-2.0-flash-001", // 使用免费且智能的模型
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: "你是一个专业的美食推荐助手。请根据用户喜好、当前场景和候选菜谱，推荐最适合的菜品。",
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
			Temperature: 0.7,
			MaxTokens:   1000,
		},
	)

	if err != nil {
		return nil, fmt.Errorf("LLM 调用失败: %w", err)
	}

	// 5. 解析 LLM 响应
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("LLM 未返回结果")
	}

	content := resp.Choices[0].Message.Content
	logger.Infof("[Recommend] LLM 响应: %s", content)

	// 去掉 markdown 代码块标记（```json ... ```）
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		if idx := strings.LastIndex(content, "```"); idx != -1 {
			content = content[:idx]
		}
		content = strings.TrimSpace(content)
	} else if strings.HasPrefix(content, "```") {
		// 处理 ``` 开头的情况
		content = strings.TrimPrefix(content, "```")
		if idx := strings.LastIndex(content, "```"); idx != -1 {
			content = content[:idx]
		}
		content = strings.TrimSpace(content)
	}

	var llmResult LLMRecommendation
	if err := json.Unmarshal([]byte(content), &llmResult); err != nil {
		return nil, fmt.Errorf("解析 LLM 响应失败: %w, 响应内容: %s", err, content)
	}

	return &llmResult, nil
}

// buildRecommendPrompt 构建推荐 Prompt
func (s *Service) buildRecommendPrompt(result *Result, userHistory *UserHistory, candidatesJSON string, limit int) string {
	prompt := fmt.Sprintf(`请根据以下信息推荐 %d 道菜：

## 当前场景
- 天气：%s，温度 %.0f°C
- 用餐时间：%s
- 季节：%s

`, limit, result.Weather.Weather, result.Weather.Temperature, getMealTimeChinese(result.MealTime), getSeasonChinese(result.Season))

	// 添加用户历史
	if userHistory != nil && len(userHistory.FavoriteRecipes) > 0 {
		prompt += "## 用户喜好（基于收藏历史）\n"
		for i, r := range userHistory.FavoriteRecipes {
			if i >= 10 { // 最多展示 10 个
				break
			}
			prompt += fmt.Sprintf("- %s（%s）: %s\n", r.Name, r.Category, joinStrings(r.Tags, "、"))
		}
		prompt += "\n"
	}

	prompt += fmt.Sprintf(`## 候选菜谱
%s

## 要求
1. 从候选菜谱中选择 %d 道最适合的菜品
2. 综合考虑：当前场景、用户喜好、菜品多样性
3. 生成一句温馨的推荐理由（不超过50字）

## 输出格式
请直接返回纯 JSON，不要使用 markdown 代码块包裹。
格式如下：
{
  "recipe_ids": ["id1", "id2", "id3"],
  "reason": "推荐理由"
}`, candidatesJSON, limit)

	return prompt
}

// queryRecipesByIDs 根据 ID 查询菜谱
func (s *Service) queryRecipesByIDs(ids []string) ([]models.Recipe, error) {
	if len(ids) == 0 {
		return []models.Recipe{}, nil
	}

	var recipes []models.Recipe
	err := s.db.Where("recipe_id IN ?", ids).Find(&recipes).Error
	return recipes, err
}

// fillTags 填充菜谱的标签信息
func (s *Service) fillTags(recipes []models.Recipe) error {
	if len(recipes) == 0 {
		return nil
	}

	recipeIDs := make([]string, len(recipes))
	for i, r := range recipes {
		recipeIDs[i] = r.RecipeID
	}

	var tags []models.Tag
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&tags).Error; err != nil {
		return err
	}

	recipeTagsMap := make(map[string][]models.Tag)
	for _, t := range tags {
		recipeTagsMap[t.RecipeID] = append(recipeTagsMap[t.RecipeID], t)
	}

	for i := range recipes {
		recipes[i].Tags = recipeTagsMap[recipes[i].RecipeID]
	}

	return nil
}

// getFallbackRecommendations 降级方案：返回随机菜谱
func (s *Service) getFallbackRecommendations(result *Result, limit int) (*Result, error) {
	var recipes []models.Recipe
	err := s.db.Order("RANDOM()").Limit(limit).Find(&recipes).Error
	if err != nil {
		return nil, err
	}

	s.fillTags(recipes)

	result.Recipes = recipes
	result.Reason = "为您推荐一些美味菜品"

	return result, nil
}

// 辅助函数
func getTemperatureFeeling(temp float64) string {
	switch {
	case temp < 5:
		return "cold"
	case temp < 15:
		return "cool"
	case temp < 25:
		return "warm"
	default:
		return "hot"
	}
}

func getMealTimeChinese(mealTime string) string {
	names := map[string]string{
		"breakfast": "早餐",
		"lunch":     "午餐",
		"afternoon": "下午茶",
		"dinner":    "晚餐",
		"night":     "夜宵",
	}
	if name, ok := names[mealTime]; ok {
		return name
	}
	return "用餐"
}

func getSeasonChinese(season string) string {
	names := map[string]string{
		"spring": "春季",
		"summer": "夏季",
		"autumn": "秋季",
		"winter": "冬季",
	}
	if name, ok := names[season]; ok {
		return name
	}
	return season
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
