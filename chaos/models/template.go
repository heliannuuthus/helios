package models

import (
	"time"
)

// EmailTemplate 邮件模板
type EmailTemplate struct {
	ID          uint       `gorm:"primaryKey;autoIncrement;column:_id"`
	TemplateID  string     `gorm:"column:template_id;size:64;not null;uniqueIndex"`
	Name        string     `gorm:"column:name;size:128;not null"`
	Description *string    `gorm:"column:description;size:512"`
	Subject     string     `gorm:"column:subject;size:256;not null"`
	Content     string     `gorm:"column:content;type:text;not null"`
	Type        string     `gorm:"column:type;size:32;not null;default:'html'"`
	Variables   *string    `gorm:"column:variables;type:text"`
	ServiceID   *string    `gorm:"column:service_id;size:32;index"`
	IsBuiltin   bool       `gorm:"column:is_builtin;not null;default:false"`
	IsEnabled   bool       `gorm:"column:is_enabled;not null;default:true"`
	CreatedAt   time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time  `gorm:"column:updated_at;not null"`
	DeletedAt   *time.Time `gorm:"column:deleted_at;index"`
}

func (EmailTemplate) TableName() string {
	return "t_email_template"
}
