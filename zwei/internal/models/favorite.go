package models

import (
	"time"
)

// Favorite 收藏表
// 关联 auth.t_user.id（认证模块的用户表）
type Favorite struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	UserID    string    `gorm:"not null;index:idx_t_favorite_user_id;column:user_id;size:64" json:"-"` // 关联 t_auth_user.id
	RecipeID  string    `gorm:"not null;index:idx_t_favorite_recipe_id;column:recipe_id;size:64" json:"recipe_id"`
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`

	// 关联关系
	Recipe *Recipe `gorm:"foreignKey:RecipeID;references:RecipeID" json:"recipe,omitempty"`
}

func (Favorite) TableName() string {
	return "t_favorite"
}
