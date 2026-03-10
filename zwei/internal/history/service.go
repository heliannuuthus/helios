package history

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/zwei/internal/models"
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
