package models

import "time"

// UserPreference 用户偏好表
// 存储用户选择的偏好选项（口味、忌口、过敏）
// 关联 auth.t_user.id（认证模块的用户表）
type UserPreference struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	UserID    string    `gorm:"not null;index;column:user_id;size:64" json:"-"`   // 关联 t_auth_user.id
	TagValue  string    `gorm:"not null;index;column:tag_value;size:50" json:"-"` // 关联 t_tag.value
	TagType   TagType   `gorm:"not null;index;column:tag_type;size:20" json:"-"`  // 关联 t_tag.type（冗余字段，优化查询）
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at" json:"updated_at"`
}

func (UserPreference) TableName() string {
	return "t_user_preference"
}

// UserPreferenceResponse 用户偏好响应（包含标签信息）
type UserPreferenceResponse struct {
	TagValue string `json:"value"` // 标签值
	TagLabel string `json:"label"` // 标签显示名称
	TagType  string `json:"type"`  // 标签类型
}

// UserPreferencesByType 按类型分组的用户偏好
type UserPreferencesByType struct {
	Flavors   []UserPreferenceResponse `json:"flavors"`   // 口味偏好
	Taboos    []UserPreferenceResponse `json:"taboos"`    // 忌口偏好
	Allergies []UserPreferenceResponse `json:"allergies"` // 过敏偏好
}
