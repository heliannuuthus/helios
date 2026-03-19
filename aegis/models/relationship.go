package models

import "time"

// Relationship 权限关系（从 proto 转换）
type Relationship struct {
	ID          uint       `json:"_id"`
	ServiceID   string     `json:"service_id"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	Relation    string     `json:"relation"`
	ObjectType  string     `json:"object_type"`
	ObjectID    string     `json:"object_id"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
