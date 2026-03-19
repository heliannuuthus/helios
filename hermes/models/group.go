package models

import "time"

// Group 用户组
type Group struct {
	ID          uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	GroupID     string    `gorm:"column:group_id;size:64;not null;uniqueIndex" json:"group_id"`
	ServiceID   string    `gorm:"column:service_id;size:32;not null;index" json:"service_id"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
	Name        string    `gorm:"column:name;size:128;not null" json:"name"`
	Description *string   `gorm:"column:description;size:512" json:"description,omitempty"`
}

func (Group) TableName() string { return "t_group" }

func (g Group) PrimaryKey() uint { return g.ID }
