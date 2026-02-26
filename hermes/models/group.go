package models

import (
	"time"
)

// Group 用户组
type Group struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	GroupID   string `gorm:"column:group_id;size:64;not null;uniqueIndex"`
	ServiceID string `gorm:"column:service_id;size:32;not null;index"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	// 变长字段
	Name        string  `gorm:"column:name;size:128;not null"`
	Description *string `gorm:"column:description;size:512"`
}

func (Group) TableName() string {
	return "t_group"
}
