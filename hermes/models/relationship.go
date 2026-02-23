package models

import (
	"time"
)

// Relationship 权限关系（ReBAC）
type Relationship struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	ServiceID   string `gorm:"column:service_id;size:32;not null"`
	SubjectType string `gorm:"column:subject_type;size:32;not null"`
	SubjectID   string `gorm:"column:subject_id;size:64;not null"`
	Relation    string `gorm:"column:relation;size:32;not null"`
	ObjectType  string `gorm:"column:object_type;size:32;not null"`
	ObjectID    string `gorm:"column:object_id;size:128;not null"`
	// 时间戳
	CreatedAt time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt *time.Time `gorm:"column:expires_at"`
}

func (Relationship) TableName() string {
	return "t_relationship"
}
