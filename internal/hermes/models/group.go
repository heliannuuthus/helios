package models

import (
	"time"
)

// Group 用户组
type Group struct {
	ID          uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	GroupID     string    `gorm:"column:group_id;size:64;not null;uniqueIndex"`
	Name        string    `gorm:"column:name;size:128;not null"`
	Description *string   `gorm:"column:description;type:text"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

func (Group) TableName() string {
	return "t_group"
}
