package models

import (
	"time"
)

// Relationship 权限关系（ReBAC）
type Relationship struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	// 固定长度字段
	ServiceID   string     `gorm:"column:service_id;size:32;not null" json:"service_id"`
	SubjectType string     `gorm:"column:subject_type;size:32;not null" json:"subject_type"`
	SubjectID   string     `gorm:"column:subject_id;size:64;not null" json:"subject_id"`
	Relation    string     `gorm:"column:relation;size:32;not null" json:"relation"`
	ObjectType  string     `gorm:"column:object_type;size:32;not null" json:"object_type"`
	ObjectID    string     `gorm:"column:object_id;size:128;not null" json:"object_id"`
	CreatedAt   time.Time  `gorm:"column:created_at;not null" json:"created_at"`
	ExpiresAt   *time.Time `gorm:"column:expires_at" json:"expires_at,omitempty"`
}

func (Relationship) TableName() string {
	return "t_relationship"
}

func (r Relationship) PrimaryKey() uint { return r.ID }
