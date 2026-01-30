package favorite

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/zwei/models"
)

// Service 收藏服务
type Service struct {
	db *gorm.DB
}

// NewService 创建收藏服务
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// AddFavorite 添加收藏
func (s *Service) AddFavorite(openID, recipeID string) (*models.Favorite, error) {
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", recipeID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("菜谱不存在")
		}
		return nil, err
	}

	var existing models.Favorite
	err := s.db.Where("user_id = ? AND recipe_id = ?", openID, recipeID).First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	favorite := models.Favorite{
		UserID:    openID,
		RecipeID:  recipeID,
		CreatedAt: time.Now(),
	}

	if err := s.db.Create(&favorite).Error; err != nil {
		return nil, err
	}

	return &favorite, nil
}

// RemoveFavorite 取消收藏
func (s *Service) RemoveFavorite(openID, recipeID string) error {
	result := s.db.Where("user_id = ? AND recipe_id = ?", openID, recipeID).Delete(&models.Favorite{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// IsFavorite 检查是否已收藏
func (s *Service) IsFavorite(openID, recipeID string) (bool, error) {
	var count int64
	err := s.db.Model(&models.Favorite{}).Where("user_id = ? AND recipe_id = ?", openID, recipeID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetFavorites 获取收藏列表
func (s *Service) GetFavorites(openID, category, search string, limit, offset int) ([]models.Favorite, int64, error) {
	allFavorites, err := s.fetchUserFavorites(openID)
	if err != nil {
		return nil, 0, err
	}

	if len(allFavorites) == 0 {
		return []models.Favorite{}, 0, nil
	}

	recipeMap, err := s.fetchRecipeMap(allFavorites)
	if err != nil {
		return nil, 0, err
	}

	filtered := s.filterFavorites(allFavorites, recipeMap, category, search)
	total := int64(len(filtered))

	return paginate(filtered, offset, limit), total, nil
}

// fetchUserFavorites 获取用户所有收藏
func (s *Service) fetchUserFavorites(openID string) ([]models.Favorite, error) {
	var favorites []models.Favorite
	err := s.db.Where("user_id = ?", openID).
		Order("created_at DESC").
		Find(&favorites).Error
	return favorites, err
}

// fetchRecipeMap 获取菜谱映射
func (s *Service) fetchRecipeMap(favorites []models.Favorite) (map[string]*models.Recipe, error) {
	recipeIDs := make([]string, len(favorites))
	for i, f := range favorites {
		recipeIDs[i] = f.RecipeID
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

// filterFavorites 筛选收藏
func (s *Service) filterFavorites(favorites []models.Favorite, recipeMap map[string]*models.Recipe, category, search string) []models.Favorite {
	var filtered []models.Favorite
	for i := range favorites {
		recipe, ok := recipeMap[favorites[i].RecipeID]
		if !ok {
			continue
		}

		if !matchCategory(recipe, category) {
			continue
		}

		if !matchSearch(recipe, search) {
			continue
		}

		favorites[i].Recipe = recipe
		filtered = append(filtered, favorites[i])
	}
	return filtered
}

// matchCategory 检查分类是否匹配
func matchCategory(recipe *models.Recipe, category string) bool {
	if category == "" {
		return true
	}
	return recipe.Category == category
}

// matchSearch 检查搜索关键词是否匹配
func matchSearch(recipe *models.Recipe, search string) bool {
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

// paginate 分页
func paginate[T any](items []T, offset, limit int) []T {
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

// GetFavoriteRecipeIDs 批量检查收藏状态
func (s *Service) GetFavoriteRecipeIDs(openID string, recipeIDs []string) ([]string, error) {
	var favorites []models.Favorite
	err := s.db.Select("recipe_id").
		Where("user_id = ? AND recipe_id IN ?", openID, recipeIDs).
		Find(&favorites).Error

	if err != nil {
		return nil, err
	}

	result := make([]string, len(favorites))
	for i, f := range favorites {
		result[i] = f.RecipeID
	}

	return result, nil
}
