package models

import (
	"time"
)

// Relationship 权限关系
type Relationship struct {
	ID          uint       `gorm:"primaryKey;autoIncrement;column:_id"`
	ServiceID   string     `gorm:"column:service_id;size:32;not null;index"`
	SubjectType string    `gorm:"column:subject_type;size:32;not null;index"`
	SubjectID   string     `gorm:"column:subject_id;size:64;not null"`
	Relation    string     `gorm:"column:relation;size:32;not null"`
	ObjectType  string     `gorm:"column:object_type;size:32;not null"`
	ObjectID    string     `gorm:"column:object_id;size:128;not null"`
	CreatedAt   time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt   *time.Time `gorm:"column:expires_at"`
}

func (Relationship) TableName() string {
	return "t_relationship"
}
