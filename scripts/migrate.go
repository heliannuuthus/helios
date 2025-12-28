//go:build ignore
// +build ignore

// 数据库迁移脚本
// 运行: go run scripts/migrate.go [db_path]
package main

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// StringSlice JSON 存储的字符串数组
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	return json.Marshal(s)
}

func (s *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("无法将值转换为 StringSlice")
	}

	return json.Unmarshal(bytes, s)
}

// User 用户信息
type User struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	OpenID    string    `gorm:"not null;uniqueIndex;column:openid;size:64"`
	TOpenID   string    `gorm:"not null;uniqueIndex;column:t_openid;size:64"`
	Nickname  string    `gorm:"not null;column:nickname;size:64"`
	Avatar    string    `gorm:"not null;column:avatar;size:512"`
	CreatedAt time.Time `gorm:"not null;column:created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at"`
}

func (User) TableName() string {
	return "users"
}

// RefreshToken 刷新令牌
type RefreshToken struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	OpenID    string    `gorm:"not null;index;column:openid;size:64"`
	Token     string    `gorm:"not null;uniqueIndex;size:128"`
	ExpiresAt time.Time `gorm:"not null;column:expires_at"`
	CreatedAt time.Time `gorm:"not null;column:created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// Recipe 菜谱
type Recipe struct {
	ID               uint        `gorm:"primaryKey;autoIncrement;column:_id"`
	RecipeID         string      `gorm:"uniqueIndex;not null;column:recipe_id;size:32"`
	Name             string      `gorm:"uniqueIndex;not null;size:128"`
	Description      *string     `gorm:"type:text"`
	Images           StringSlice `gorm:"type:json;default:'[]'"`
	Category         string      `gorm:"index"`
	Difficulty       int
	Servings         int
	PrepTimeMinutes  *int      `gorm:"column:prep_time_minutes"`
	CookTimeMinutes  *int      `gorm:"column:cook_time_minutes"`
	TotalTimeMinutes *int      `gorm:"column:total_time_minutes"`
	CreatedAt        time.Time `gorm:"not null;column:created_at;default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time `gorm:"not null;column:updated_at;default:CURRENT_TIMESTAMP"`
}

func (Recipe) TableName() string {
	return "recipes"
}

// Ingredient 食材
type Ingredient struct {
	ID           uint    `gorm:"primaryKey;autoIncrement;column:_id"`
	RecipeID     string  `gorm:"not null;index;column:recipe_id;size:16"`
	Name         string  `gorm:"not null;size:64"`
	Category     *string `gorm:"index;size:32"`
	Quantity     *float64
	Unit         *string `gorm:"size:16"`
	TextQuantity string  `gorm:"not null;column:text_quantity;size:32"`
	Notes        *string
	CreatedAt    time.Time `gorm:"not null;column:created_at;default:CURRENT_TIMESTAMP"`
	UpdatedAt    time.Time `gorm:"not null;column:updated_at;default:CURRENT_TIMESTAMP"`
}

func (Ingredient) TableName() string {
	return "ingredients"
}

// Step 步骤
type Step struct {
	ID          uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	RecipeID    string    `gorm:"not null;index;column:recipe_id;size:16"`
	Step        int       `gorm:"not null"`
	Description string    `gorm:"not null;type:text"`
	CreatedAt   time.Time `gorm:"not null;column:created_at;default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time `gorm:"not null;column:updated_at;default:CURRENT_TIMESTAMP"`
}

func (Step) TableName() string {
	return "steps"
}

// AdditionalNote 小贴士
type AdditionalNote struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	RecipeID  string    `gorm:"not null;index;column:recipe_id;size:16"`
	Note      string    `gorm:"not null;type:text"`
	CreatedAt time.Time `gorm:"not null;column:created_at;default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at;default:CURRENT_TIMESTAMP"`
}

func (AdditionalNote) TableName() string {
	return "additional_notes"
}

// Favorite 收藏
type Favorite struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	OpenID    string    `gorm:"not null;index:idx_favorite_user;column:openid;size:64"`
	RecipeID  string    `gorm:"not null;index:idx_favorite_recipe;column:recipe_id;size:16"`
	CreatedAt time.Time `gorm:"not null;column:created_at;default:CURRENT_TIMESTAMP"`
}

func (Favorite) TableName() string {
	return "favorites"
}

// Tag 标签（直接关联菜谱）
type Tag struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	RecipeID  string    `gorm:"not null;index;column:recipe_id;size:16"`
	Value     string    `gorm:"not null;index;size:50"`
	Label     string    `gorm:"not null;size:50"`
	Type      string    `gorm:"not null;index;size:20"`
	CreatedAt time.Time `gorm:"not null;column:created_at;default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at;default:CURRENT_TIMESTAMP"`
}

func (Tag) TableName() string {
	return "tags"
}

// IngredientCategory 食材分类
type IngredientCategory struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	Key       string    `gorm:"uniqueIndex;not null;size:32"`
	Label     string    `gorm:"not null;size:32"`
	CreatedAt time.Time `gorm:"not null;column:created_at;default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at;default:CURRENT_TIMESTAMP"`
}

func (IngredientCategory) TableName() string {
	return "ingredient_categories"
}

// 需要添加时间字段的表
var tablesToAddTimestamps = []string{
	"recipes",
	"ingredients",
	"steps",
	"additional_notes",
	"tags",
}

// 检查列是否存在
func columnExists(db *gorm.DB, table, column string) bool {
	var count int64
	db.Raw("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&count)
	return count > 0
}

// 添加时间字段到现有表
func addTimestampColumns(db *gorm.DB) {
	now := time.Now().Format("2006-01-02 15:04:05")

	for _, table := range tablesToAddTimestamps {
		// 添加 created_at
		if !columnExists(db, table, "created_at") {
			sql := fmt.Sprintf("ALTER TABLE %s ADD COLUMN created_at DATETIME NOT NULL DEFAULT '%s'", table, now)
			if err := db.Exec(sql).Error; err != nil {
				log.Printf("警告: %s 添加 created_at 失败: %v", table, err)
			} else {
				fmt.Printf("  + %s.created_at\n", table)
			}
		}

		// 添加 updated_at
		if !columnExists(db, table, "updated_at") {
			sql := fmt.Sprintf("ALTER TABLE %s ADD COLUMN updated_at DATETIME NOT NULL DEFAULT '%s'", table, now)
			if err := db.Exec(sql).Error; err != nil {
				log.Printf("警告: %s 添加 updated_at 失败: %v", table, err)
			} else {
				fmt.Printf("  + %s.updated_at\n", table)
			}
		}
	}

	// ingredients 表还需要添加 category 字段
	if !columnExists(db, "ingredients", "category") {
		if err := db.Exec("ALTER TABLE ingredients ADD COLUMN category VARCHAR(32)").Error; err != nil {
			log.Printf("警告: ingredients 添加 category 失败: %v", err)
		} else {
			fmt.Println("  + ingredients.category")
		}
	}
}

func main() {
	// 数据库路径
	dbPath := "db/choosy.db"
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}

	// 确保目录存在
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("创建目录失败: %v", err)
		}
	}

	// 连接数据库
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	fmt.Printf("正在迁移数据库: %s\n\n", dbPath)

	// Step 1: 添加时间字段到现有表（使用 ALTER TABLE）
	fmt.Println("[1/3] 添加新字段到现有表...")
	addTimestampColumns(db)
	fmt.Println()

	// Step 2: 创建新表 (ingredient_categories)
	fmt.Println("[2/3] 创建新表...")
	if err := db.AutoMigrate(&IngredientCategory{}); err != nil {
		log.Printf("警告: 创建 ingredient_categories 表失败: %v", err)
	} else {
		fmt.Println("  ✓ ingredient_categories")
	}
	fmt.Println()

	// Step 3: 创建索引
	fmt.Println("[3/3] 创建索引...")
	indexes := []struct {
		name  string
		table string
		col   string
	}{
		{"idx_ingredients_category", "ingredients", "category"},
	}

	for _, idx := range indexes {
		sql := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)", idx.name, idx.table, idx.col)
		if err := db.Exec(sql).Error; err != nil {
			log.Printf("警告: 创建索引 %s 失败: %v", idx.name, err)
		} else {
			fmt.Printf("  ✓ %s\n", idx.name)
		}
	}

	fmt.Println("\n✓ 迁移完成")

	// 打印表信息
	var tables []string
	db.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables)
	fmt.Printf("当前表: %v\n", tables)
}
