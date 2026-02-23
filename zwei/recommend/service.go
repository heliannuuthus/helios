package recommend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/sashabaranov/go-openai"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/pkg/amap"
	"github.com/heliannuuthus/helios/pkg/helpers"
	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/zwei/config"
	"github.com/heliannuuthus/helios/zwei/internal/models"
	"github.com/heliannuuthus/helios/zwei/tag"
)

// Service 推荐服务
type Service struct {
	db        *gorm.DB
	amap      *amap.Client
	llmClient *openai.Client
}

// ContextRequest 上下文请求
type ContextRequest struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timestamp int64   `json:"timestamp"`
}

// LocationInfo 位置信息
type LocationInfo struct {
	Province string `json:"province"`
	City     string `json:"city"`
	District string `json:"district"`
	Adcode   string `json:"-"`
}

// TimeInfo 时间信息
type TimeInfo struct {
	Timestamp int64  `json:"timestamp"`
	MealTime  string `json:"meal_time"`
	Season    string `json:"season"`
	DayOfWeek int    `json:"day_of_week"`
	Hour      int    `json:"hour"`
}

// ContextResponse 上下文响应
type ContextResponse struct {
	Location *LocationInfo        `json:"location"`
	Weather  *WeatherInfoResponse `json:"weather"`
	Time     *TimeInfo            `json:"time"`
}

// GetContext 获取推荐上下文信息（位置、天气、时间）
func (s *Service) GetContext(req *ContextRequest) *ContextResponse {
	response := &ContextResponse{}

	// 获取位置信息
	logger.Debugf("[Recommend] 获取位置 - Lat: %.6f, Lng: %.6f", req.Latitude, req.Longitude)
	location, err := s.amap.GetLocation(req.Latitude, req.Longitude)
	if err != nil {
		logger.Errorf("[Recommend] 高德逆地理编码失败 - Lat: %.6f, Lng: %.6f, Error: %v", req.Latitude, req.Longitude, err)
	} else {
		response.Location = &LocationInfo{
			Province: location.Province,
			City:     location.City,
			District: location.District,
			Adcode:   location.Adcode,
		}

		// 获取天气信息
		if location.Adcode != "" {
			weather, err := s.amap.GetWeatherByAdcode(location.Adcode)
			if err == nil {
				response.Weather = &WeatherInfoResponse{
					Temperature: weather.Temperature,
					Humidity:    weather.Humidity,
					Weather:     weather.Weather,
					Icon:        "", // 高德 API 可能不返回 icon，需要根据 weather 字段生成
				}
			}
		}
	}

	// 构建时间信息
	t := time.UnixMilli(req.Timestamp)
	response.Time = &TimeInfo{
		Timestamp: req.Timestamp,
		MealTime:  helpers.GetMealTime(t),
		Season:    helpers.GetSeason(t),
		DayOfWeek: int(t.Weekday()),
		Hour:      t.Hour(),
	}

	return response
}

// WeatherInfo 天气信息（内部使用）
type WeatherInfo struct {
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
	Weather     string  `json:"weather"`
	City        string  `json:"city"`
}

// WeatherInfoResponse 天气信息响应（API 使用）
type WeatherInfoResponse struct {
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
	Weather     string  `json:"weather"`
	Icon        string  `json:"icon"`
}

// Context 推荐上下文
type Context struct {
	UserID     string   `json:"user_id,omitempty"`
	Latitude   float64  `json:"latitude"`
	Longitude  float64  `json:"longitude"`
	Timestamp  int64    `json:"timestamp"`
	ExcludeIDs []string `json:"exclude_ids,omitempty"` // 排除的菜谱 ID（换一批时传入）
}

// RecipeWithReason 带推荐理由的菜谱
type RecipeWithReason struct {
	Recipe models.Recipe
	Reason string
}

// Result 推荐结果（返回给调用方）
type Result struct {
	Recipes []RecipeWithReason
	Summary string // LLM 生成的一句话整体评价
}

// recommendContext 推荐上下文（内部使用，用于构建 prompt）
type recommendContext struct {
	Weather     *WeatherInfo
	MealTime    string
	Season      string
	Temperature string
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

// LLMRecommendationItem 单个推荐项
type LLMRecommendationItem struct {
	RecipeID string `json:"recipe_id" jsonschema:"description=推荐的菜谱ID"`
	Name     string `json:"name" jsonschema:"description=菜谱名称"`
	Reason   string `json:"reason" jsonschema:"description=推荐理由,30-50字"`
}

// LLMRecommendation LLM 推荐结果
type LLMRecommendation struct {
	Recommendations []LLMRecommendationItem `json:"recommendations" jsonschema:"description=推荐列表,minItems=1"`
	Summary         string                  `json:"summary" jsonschema:"description=一句话整体评价,例如:今天天气凉爽适合来点暖胃的家常菜"`
}

// JSONSchema 实现 json.Marshaler，用于结构化输出
type JSONSchema struct {
	schema interface{}
}

func (j JSONSchema) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.schema)
}

// generateSchema 生成 JSON Schema
func generateSchema[T any]() interface{} {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}
	var v T
	schema := reflector.Reflect(v)
	return schema
}

// recommendationSchema 推荐结果的 JSON Schema
var recommendationSchema = generateSchema[LLMRecommendation]()

// addReasoningEnabled 为 MiMo-V2-Flash 模型添加 reasoning_enabled 参数
// 注意：go-openai 库目前不支持 reasoning_enabled 字段
// 根据 OpenRouter 文档，MiMo-V2-Flash 在使用工具调用时应关闭 reasoning mode
// 由于库的限制，这里只记录日志，实际参数需要通过修改 go-openai 库或使用自定义 HTTP 客户端来传递
// 参考：https://openrouter.ai/docs/reasoning-tokens
func addReasoningEnabled(req *openai.ChatCompletionRequest, enabled bool) {
	// 记录日志，提醒开发者注意
	logger.Infof("[Recommend] MiMo-V2-Flash 模型：reasoning_enabled=%v (当前 go-openai 库不支持此参数，需手动修改库或使用自定义 HTTP 客户端)", enabled)

	// TODO: 如果需要完整支持，可以考虑：
	// 1. 使用 reflect 包修改请求结构（可能不稳定）
	// 2. Fork go-openai 库并添加 reasoning_enabled 字段支持
	// 3. 使用自定义 HTTP 客户端直接调用 OpenRouter API
}

// NewService 创建推荐服务
func NewService(db *gorm.DB) *Service {
	cfg := config.Cfg()
	// 配置 OpenRouter 客户端
	apiKey := cfg.GetString("openrouter.api-key")
	clientConfig := openai.DefaultConfig(apiKey)
	clientConfig.BaseURL = "https://openrouter.ai/api/v1"

	return &Service{
		db:        db,
		amap:      amap.NewClient(cfg.GetString("amap.api-key")),
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

	// 2. 构建推荐上下文（用于生成 prompt）
	t := time.UnixMilli(ctx.Timestamp)
	recCtx := &recommendContext{
		Weather: &WeatherInfo{
			Temperature: weather.Temperature,
			Humidity:    weather.Humidity,
			Weather:     weather.Weather,
		},
		MealTime:    helpers.GetMealTime(t),
		Season:      helpers.GetSeason(t),
		Temperature: getTemperatureFeeling(weather.Temperature),
	}

	// 3. 获取用户历史（如果有用户 ID）
	var userHistory *UserHistory
	if ctx.UserID != "" {
		userHistory, err = s.getUserHistory(ctx.UserID)
		if err != nil {
			logger.Warnf("获取用户历史失败: %v", err)
		}
	}

	// 4. 使用 LLM 生成推荐
	llmResult, err := s.getLLMRecommendations(recCtx, userHistory, limit, ctx.ExcludeIDs)
	if err != nil {
		logger.Errorf("[Recommend] LLM 推荐失败: %v, 错误详情: %+v", err, err)
		return nil, fmt.Errorf("LLM 推荐失败: %w", err)
	}

	// 5. 提取菜谱 ID 并查询详情，同时保留理由映射
	recipeIDs := make([]string, len(llmResult.Recommendations))
	reasonMap := make(map[string]string)
	for i, rec := range llmResult.Recommendations {
		recipeIDs[i] = rec.RecipeID
		reasonMap[rec.RecipeID] = rec.Reason
	}

	logger.Infof("[Recommend] LLM 推荐的菜谱 ID: %v", recipeIDs)

	recipes, err := s.queryRecipesByIDs(recipeIDs)
	if err != nil {
		logger.Errorf("查询菜谱失败: %v", err)
		return nil, fmt.Errorf("查询菜谱失败: %w", err)
	}

	logger.Infof("[Recommend] 数据库查询到的菜谱数量: %d", len(recipes))

	// 6. 填充标签信息
	if err := s.fillTags(recipes); err != nil {
		logger.Warnf("填充标签失败: %v", err)
	}

	// 7. 构建 recipe 查找表，按 LLM 返回的顺序组装结果
	recipeMap := make(map[string]models.Recipe)
	for _, r := range recipes {
		recipeMap[r.RecipeID] = r
	}

	// 按 LLM 推荐的顺序组装，跳过不存在的菜谱
	result.Recipes = make([]RecipeWithReason, 0, len(llmResult.Recommendations))
	for _, rec := range llmResult.Recommendations {
		if recipe, ok := recipeMap[rec.RecipeID]; ok {
			result.Recipes = append(result.Recipes, RecipeWithReason{
				Recipe: recipe,
				Reason: rec.Reason,
			})
		} else {
			logger.Warnf("[Recommend] 菜谱 ID 不存在: %s", rec.RecipeID)
		}
	}

	// 设置 LLM 生成的整体评价
	result.Summary = llmResult.Summary

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
	err := s.db.Where("user_id = ?", userID).
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
		if err := s.fillTags(recipes); err != nil {
			logger.Errorf("[Recommend] 填充收藏菜谱标签失败: %v", err)
		}

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

// candidateRecipe 候选菜谱结构（用于 LLM 输入）
type candidateRecipe struct {
	RecipeID         string   `json:"recipe_id"`
	Name             string   `json:"name"`
	Category         string   `json:"category"`
	Tags             []string `json:"tags"`
	Description      string   `json:"description"`
	Difficulty       int      `json:"difficulty"`
	TotalTimeMinutes *int     `json:"total_time_minutes,omitempty"`
}

// getLLMRecommendations 使用 LLM 生成推荐
func (s *Service) getLLMRecommendations(recCtx *recommendContext, userHistory *UserHistory, limit int, excludeIDs []string) (*LLMRecommendation, error) {
	// 1. 获取候选菜谱
	candidatesJSON, err := s.fetchCandidates(excludeIDs)
	if err != nil {
		return nil, err
	}

	// 2. 构建 Prompt 和工具
	prompt := s.buildRecommendPrompt(recCtx, userHistory, candidatesJSON, limit)
	tools := s.buildLLMTools()

	// 3. 初始化对话
	model := config.Cfg().GetString("openrouter.model")
	if model == "" {
		return nil, fmt.Errorf("未配置 openrouter.model，请在配置文件中设置模型")
	}

	messages := s.initLLMMessages(prompt)

	// 4. 多轮对话循环
	return s.runLLMConversation(model, messages, tools)
}

// fetchCandidates 获取候选菜谱并序列化为 JSON
func (s *Service) fetchCandidates(excludeIDs []string) (string, error) {
	var allRecipes []models.Recipe
	query := s.db.Select("recipe_id, name, category, description, difficulty, total_time_minutes")
	if len(excludeIDs) > 0 {
		query = query.Where("recipe_id NOT IN ?", excludeIDs)
	}
	if err := query.Limit(500).Find(&allRecipes).Error; err != nil {
		return "", err
	}

	if err := s.fillTags(allRecipes); err != nil {
		logger.Errorf("[Recommend] 填充候选菜谱标签失败: %v", err)
	}

	candidates := s.recipesToCandidates(allRecipes)
	candidatesJSON, err := json.Marshal(candidates, jsontext.WithIndent("  "))
	if err != nil {
		return "", fmt.Errorf("序列化候选菜谱失败: %w", err)
	}
	return string(candidatesJSON), nil
}

// recipesToCandidates 将菜谱列表转换为候选列表
func (s *Service) recipesToCandidates(recipes []models.Recipe) []candidateRecipe {
	candidates := make([]candidateRecipe, len(recipes))
	for i, r := range recipes {
		tags := make([]string, len(r.Tags))
		for j, t := range r.Tags {
			tags[j] = t.Value
		}
		desc := ""
		if r.Description != nil {
			desc = *r.Description
		}
		candidates[i] = candidateRecipe{
			RecipeID:         r.RecipeID,
			Name:             r.Name,
			Category:         r.Category,
			Tags:             tags,
			Description:      desc,
			Difficulty:       r.Difficulty,
			TotalTimeMinutes: r.TotalTimeMinutes,
		}
	}
	return candidates
}

// buildLLMTools 构建 LLM 工具定义
func (s *Service) buildLLMTools() []openai.Tool {
	return []openai.Tool{
		{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        "get_recipe_details",
				Description: "查询菜品的详细信息，包括分类、标签、描述、难度、制作时间等。当需要了解菜品的具体信息以做出更好的推荐时，可以调用此工具。",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"recipe_ids": map[string]interface{}{
							"type":        "array",
							"description": "要查询的菜品 ID 列表",
							"items":       map[string]interface{}{"type": "string"},
						},
					},
					"required": []string{"recipe_ids"},
				},
			},
		},
	}
}

// initLLMMessages 初始化 LLM 对话消息
func (s *Service) initLLMMessages(prompt string) []openai.ChatCompletionMessage {
	return []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
			Content: "你是一个专业的美食推荐助手。请根据用户喜好、当前场景和候选菜谱，推荐最适合的菜品。推荐理由需要详细、具体、有说服力。如果需要了解菜品的详细信息，可以使用 get_recipe_details 工具查询。",
		},
		{
			Role:    openai.ChatMessageRoleUser,
			Content: prompt,
		},
	}
}

// runLLMConversation 运行 LLM 多轮对话
func (s *Service) runLLMConversation(model string, messages []openai.ChatCompletionMessage, tools []openai.Tool) (*LLMRecommendation, error) {
	logger.Infof("[Recommend] 调用 LLM - Prompt 长度: %d", len(messages[1].Content))

	maxIterations := 5
	for i := 0; i < maxIterations; i++ {
		req := s.buildLLMRequest(model, messages, tools)

		logger.Infof("[Recommend] LLM 请求（第 %d 轮）- Model: %s, Messages: %d", i+1, model, len(messages))

		resp, err := s.llmClient.CreateChatCompletion(context.Background(), req)
		if err != nil {
			return nil, s.handleLLMError(model, err)
		}

		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("LLM 未返回结果 (model: %s)", model)
		}

		choice := resp.Choices[0]
		messages = append(messages, choice.Message)

		// 处理工具调用
		if len(choice.Message.ToolCalls) > 0 {
			toolMessages := s.handleToolCalls(choice.Message.ToolCalls)
			messages = append(messages, toolMessages...)
			continue
		}

		// 解析最终结果
		return s.parseLLMResponse(choice.Message.Content)
	}

	return nil, fmt.Errorf("LLM 调用超过最大迭代次数")
}

// buildLLMRequest 构建 LLM 请求
func (s *Service) buildLLMRequest(model string, messages []openai.ChatCompletionMessage, tools []openai.Tool) openai.ChatCompletionRequest {
	req := openai.ChatCompletionRequest{
		Model:       model,
		Messages:    messages,
		Tools:       tools,
		Temperature: 0.3,
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
			JSONSchema: &openai.ChatCompletionResponseFormatJSONSchema{
				Name:        "recommendation",
				Description: "美食推荐结果",
				Schema:      JSONSchema{schema: recommendationSchema},
				Strict:      true,
			},
		},
	}

	if strings.Contains(model, "mimo-v2-flash") {
		addReasoningEnabled(&req, false)
	}

	return req
}

// handleLLMError 处理 LLM 错误
func (s *Service) handleLLMError(model string, err error) error {
	apiErr := &openai.APIError{}
	if errors.As(err, &apiErr) {
		logger.Errorf("[Recommend] LLM 调用失败 - Model: %s, APIError详情: Code=%d, HTTPStatusCode=%d, Message=%s",
			model, apiErr.Code, apiErr.HTTPStatusCode, apiErr.Message)
		return fmt.Errorf("LLM 调用失败 (model: %s): status code: %d, message: %s",
			model, apiErr.Code, apiErr.Message)
	}
	logger.Errorf("[Recommend] LLM 调用失败 - Model: %s, 错误类型: %T, 错误信息: %v", model, err, err)
	return fmt.Errorf("LLM 调用失败 (model: %s): %w", model, err)
}

// handleToolCalls 处理工具调用
func (s *Service) handleToolCalls(toolCalls []openai.ToolCall) []openai.ChatCompletionMessage {
	logger.Infof("[Recommend] LLM 请求查询菜品详情，调用次数: %d", len(toolCalls))

	var messages []openai.ChatCompletionMessage
	for _, toolCall := range toolCalls {
		if toolCall.Function.Name != "get_recipe_details" {
			continue
		}

		ids := s.parseRecipeIDs(toolCall.Function.Arguments)
		if len(ids) == 0 {
			continue
		}

		details := s.getRecipeDetails(ids)
		detailsJSON, err := json.Marshal(details, jsontext.WithIndent("  "))
		if err != nil {
			logger.Errorf("[Recommend] 序列化菜品详情失败: %v", err)
			continue
		}

		messages = append(messages, openai.ChatCompletionMessage{
			Role:       openai.ChatMessageRoleTool,
			Content:    string(detailsJSON),
			ToolCallID: toolCall.ID,
		})
	}
	return messages
}

// parseRecipeIDs 解析菜谱 ID 列表
func (s *Service) parseRecipeIDs(arguments string) []string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		logger.Errorf("[Recommend] 解析 function call 参数失败: %v", err)
		return nil
	}

	recipeIDs, ok := args["recipe_ids"].([]interface{})
	if !ok {
		logger.Errorf("[Recommend] recipe_ids 参数格式错误")
		return nil
	}

	ids := make([]string, 0, len(recipeIDs))
	for _, id := range recipeIDs {
		if idStr, ok := id.(string); ok {
			ids = append(ids, idStr)
		}
	}
	return ids
}

// parseLLMResponse 解析 LLM 响应
func (s *Service) parseLLMResponse(content string) (*LLMRecommendation, error) {
	logger.Infof("[Recommend] LLM 最终响应: %s", content)

	content = cleanMarkdownCodeBlock(content)

	var result LLMRecommendation
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("解析 LLM 响应失败: %w, 响应内容: %s", err, content)
	}
	return &result, nil
}

// cleanMarkdownCodeBlock 清理 Markdown 代码块包装
func cleanMarkdownCodeBlock(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		if idx := strings.LastIndex(content, "```"); idx != -1 {
			content = content[:idx]
		}
		content = strings.TrimSpace(content)
	} else if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
		if idx := strings.LastIndex(content, "```"); idx != -1 {
			content = content[:idx]
		}
		content = strings.TrimSpace(content)
	}
	return content
}

// buildRecommendPrompt 构建推荐 Prompt
func (s *Service) buildRecommendPrompt(recCtx *recommendContext, userHistory *UserHistory, candidatesJSON string, limit int) string {
	prompt := fmt.Sprintf(`请根据以下信息推荐 %d 道菜：

## 当前场景
- 天气：%s，温度 %.0f°C
- 用餐时间：%s
- 季节：%s

`, limit, recCtx.Weather.Weather, recCtx.Weather.Temperature, getMealTimeChinese(recCtx.MealTime), getSeasonChinese(recCtx.Season))

	// 添加用户历史
	if userHistory != nil && len(userHistory.FavoriteRecipes) > 0 {
		prompt += "## 用户口味偏好分析\n"
		prompt += "以下是用户最近收藏的菜品，仅用于分析其口味偏好（如偏好的菜系、口味、烹饪方式等），**请勿直接推荐这些已收藏的菜品**：\n"
		for i, r := range userHistory.FavoriteRecipes {
			if i >= 10 { // 最多展示 10 个
				break
			}
			tagsStr := joinStrings(r.Tags, "、")
			if tagsStr == "" {
				tagsStr = "无标签"
			}
			prompt += fmt.Sprintf("- %s（%s）标签：%s\n", r.Name, r.Category, tagsStr)
		}
		prompt += "\n从以上收藏可以推断用户的口味偏好，请基于这些偏好推荐**新的、用户可能喜欢但尚未尝试过的菜品**。\n\n"
	}

	prompt += fmt.Sprintf(`## 候选菜谱
以下是候选菜谱的详细信息，包括 ID、名称、分类、标签、描述、难度、制作时间等。

%s

## 推荐要求
1. 从候选菜谱中选择 %d 道最适合的菜品
2. **优先推荐用户没吃过的新菜品**，避免推荐用户已收藏的菜
3. 根据用户口味偏好（如偏好的菜系、口味、食材）推荐相似风格的新菜品
4. 结合当前天气、时段、季节等场景因素
5. 为每道菜生成简洁的推荐理由（30-50字），说明为何适合该用户
6. 生成一句整体评价（summary），概括这次推荐的主题或理由，例如"今天天气凉爽，为您精选几道暖胃家常菜"、"周末时光，来点轻松好做的快手菜"

请按照指定的 JSON Schema 格式返回结果。`, candidatesJSON, limit)

	return prompt
}

// getRecipeDetails 查询菜品详细信息（用于 function calling）
func (s *Service) getRecipeDetails(ids []string) []map[string]interface{} {
	if len(ids) == 0 {
		return []map[string]interface{}{}
	}

	var recipes []models.Recipe
	err := s.db.Select("recipe_id, name, category, description, difficulty, total_time_minutes, prep_time_minutes, cook_time_minutes").
		Where("recipe_id IN ?", ids).
		Find(&recipes).Error
	if err != nil {
		logger.Errorf("[Recommend] 查询菜品详情失败: %v", err)
		return []map[string]interface{}{}
	}

	if err := s.fillTags(recipes); err != nil {
		logger.Errorf("[Recommend] 填充菜品详情标签失败: %v", err)
	}

	details := make([]map[string]interface{}, len(recipes))
	for i, r := range recipes {
		tags := make([]string, len(r.Tags))
		for j, t := range r.Tags {
			tags[j] = t.Value
		}
		desc := ""
		if r.Description != nil {
			desc = *r.Description
		}

		detail := map[string]interface{}{
			"id":          r.RecipeID,
			"name":        r.Name,
			"category":    r.Category,
			"tags":        tags,
			"description": desc,
			"difficulty":  r.Difficulty,
		}

		if r.TotalTimeMinutes != nil {
			detail["total_time_minutes"] = *r.TotalTimeMinutes
		}
		if r.PrepTimeMinutes != nil {
			detail["prep_time_minutes"] = *r.PrepTimeMinutes
		}
		if r.CookTimeMinutes != nil {
			detail["cook_time_minutes"] = *r.CookTimeMinutes
		}

		details[i] = detail
	}

	return details
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

// fillTags 填充菜谱的标签信息（内存组装，避免 JOIN）
func (s *Service) fillTags(recipes []models.Recipe) error {
	if len(recipes) == 0 {
		return nil
	}

	recipeIDs := make([]string, len(recipes))
	for i, r := range recipes {
		recipeIDs[i] = r.RecipeID
	}

	// 1. 查询关联表（不 JOIN，避免连表查询）
	var recipeTags []models.RecipeTag
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipeTags).Error; err != nil {
		return err
	}

	if len(recipeTags) == 0 {
		// 没有标签，直接返回空
		for i := range recipes {
			recipes[i].Tags = []models.Tag{}
		}
		return nil
	}

	// 2. 从缓存获取标签定义（懒加载：缓存未命中时自动查询数据库）
	tagCache := tag.GetTagCache()

	// 3. 按 recipe_id 分组组装（从缓存获取标签定义）
	recipeTagsMap := make(map[string][]models.Tag)
	for _, rt := range recipeTags {
		tag, err := tagCache.Get(rt.TagType, rt.TagValue, s.db)
		if err == nil {
			recipeTagsMap[rt.RecipeID] = append(recipeTagsMap[rt.RecipeID], *tag)
		}
	}

	// 6. 填充到 recipes
	for i := range recipes {
		if tags, ok := recipeTagsMap[recipes[i].RecipeID]; ok {
			recipes[i].Tags = tags
		} else {
			recipes[i].Tags = []models.Tag{}
		}
	}

	return nil
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
