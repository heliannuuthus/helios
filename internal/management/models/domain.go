package models

import (
	"time"
)

// Domain 域
type Domain struct {
	ID          uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	DomainID    string    `gorm:"column:domain_id;size:32;not null;uniqueIndex"`
	Name        string    `gorm:"column:name;size:128;not null"`
	Description *string   `gorm:"column:description;type:text"`
	Status      int8      `gorm:"column:status;default:0"` // 0=active, 1=disabled
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

func (Domain) TableName() string {
	return "t_domain"
}
