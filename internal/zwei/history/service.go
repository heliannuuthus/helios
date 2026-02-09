package history

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/zwei/models"
)

// Service 浏览历史服务
type Service struct {
	db *gorm.DB
}

// NewService 创建浏览历史服务
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// AddViewHistory 添加浏览记录（如果已存在则更新浏览时间）
func (s *Service) AddViewHistory(openID, recipeID string) (*models.ViewHistory, error) {
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", recipeID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("菜谱不存在")
		}
		return nil, err
	}

	var existing models.ViewHistory
	err := s.db.Where("user_id = ? AND recipe_id = ?", openID, recipeID).
		Order("viewed_at DESC").
		First(&existing).Error

	if err == nil {
		// 已存在，检查距离上次浏览时间是否超过 24 小时
		now := time.Now()
		timeDiff := now.Sub(existing.ViewedAt)

		if timeDiff < 24*time.Hour {
			// 24 小时内，更新浏览时间和更新时间
			existing.ViewedAt = now
			existing.UpdatedAt = now
			if err := s.db.Save(&existing).Error; err != nil {
				return nil, err
			}
			return &existing, nil
		}
		// 超过 24 小时，创建新记录（不更新现有记录）
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 不存在或超过 24 小时，创建新记录
	now := time.Now()
	history := models.ViewHistory{
		UserID:    openID,
		RecipeID:  recipeID,
		ViewedAt:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.db.Create(&history).Error; err != nil {
		return nil, err
	}

	return &history, nil
}

// RemoveViewHistory 删除浏览记录
func (s *Service) RemoveViewHistory(openID, recipeID string) error {
	result := s.db.Where("user_id = ? AND recipe_id = ?", openID, recipeID).Delete(&models.ViewHistory{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// ClearViewHistory 清空用户的所有浏览记录
func (s *Service) ClearViewHistory(openID string) error {
	result := s.db.Where("user_id = ?", openID).Delete(&models.ViewHistory{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetViewHistory 获取浏览历史列表（数据库层过滤+分页）
func (s *Service) GetViewHistory(openID, category, search string, limit, offset int) ([]models.ViewHistory, int64, error) {
	query := s.db.Model(&models.ViewHistory{}).
		Joins("JOIN recipes ON recipes.recipe_id = view_histories.recipe_id").
		Where("view_histories.user_id = ?", openID)

	if category != "" {
		query = query.Where("recipes.category = ?", category)
	}
	if search != "" {
		like := "%" + search + "%"
		query = query.Where("(recipes.name LIKE ? OR recipes.description LIKE ?)", like, like)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []models.ViewHistory{}, 0, nil
	}

	var history []models.ViewHistory
	if err := query.Preload("Recipe").
		Order("view_histories.viewed_at DESC").
		Offset(offset).Limit(limit).
		Find(&history).Error; err != nil {
		return nil, 0, err
	}

	return history, total, nil
}

// fetchUserHistory 获取用户所有浏览历史
func (s *Service) fetchUserHistory(openID string) ([]models.ViewHistory, error) {
	var history []models.ViewHistory
	err := s.db.Where("user_id = ?", openID).
		Order("viewed_at DESC").
		Find(&history).Error
	return history, err
}

// fetchHistoryRecipeMap 获取菜谱映射
func (s *Service) fetchHistoryRecipeMap(history []models.ViewHistory) (map[string]*models.Recipe, error) {
	recipeIDs := make([]string, len(history))
	for i, h := range history {
		recipeIDs[i] = h.RecipeID
	}

	var recipes []models.Recipe
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipes).Error; err != nil {
		return nil, err
	}

	recipeMap := make(map[string]*models.Recipe)
	for i := range recipes {
		recipeMap[recipes[i].RecipeID] = &recipes[i]
	}
	return recipeMap, nil
}

// filterHistory 筛选浏览历史
func (s *Service) filterHistory(history []models.ViewHistory, recipeMap map[string]*models.Recipe, category, search string) []models.ViewHistory {
	var filtered []models.ViewHistory
	for i := range history {
		recipe, ok := recipeMap[history[i].RecipeID]
		if !ok {
			continue
		}

		if !matchHistoryCategory(recipe, category) {
			continue
		}

		if !matchHistorySearch(recipe, search) {
			continue
		}

		history[i].Recipe = recipe
		filtered = append(filtered, history[i])
	}
	return filtered
}

// matchHistoryCategory 检查分类是否匹配
func matchHistoryCategory(recipe *models.Recipe, category string) bool {
	if category == "" {
		return true
	}
	return recipe.Category == category
}

// matchHistorySearch 检查搜索关键词是否匹配
func matchHistorySearch(recipe *models.Recipe, search string) bool {
	if search == "" {
		return true
	}
	searchLower := strings.ToLower(search)
	nameLower := strings.ToLower(recipe.Name)
	if strings.Contains(nameLower, searchLower) {
		return true
	}
	if recipe.Description != nil {
		descLower := strings.ToLower(*recipe.Description)
		if strings.Contains(descLower, searchLower) {
			return true
		}
	}
	return false
}

// paginateHistory 分页
func paginateHistory(items []models.ViewHistory, offset, limit int) []models.ViewHistory {
	start := offset
	if start > len(items) {
		start = len(items)
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}
