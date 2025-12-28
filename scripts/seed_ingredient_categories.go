//go:build ignore
// +build ignore

// 食材分类初始化脚本
// 运行: go run scripts/seed_ingredient_categories.go
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// IngredientCategory 食材分类
type IngredientCategory struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	Key       string    `gorm:"uniqueIndex;not null;size:32"`
	Label     string    `gorm:"not null;size:32"`
	CreatedAt time.Time `gorm:"not null;column:created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at"`
}

func (IngredientCategory) TableName() string {
	return "ingredient_categories"
}

// 食材分类数据
var categories = []IngredientCategory{
	{Key: "meat", Label: "肉禽类"},
	{Key: "seafood", Label: "水产海鲜"},
	{Key: "vegetable", Label: "蔬菜"},
	{Key: "mushroom", Label: "菌菇"},
	{Key: "tofu", Label: "豆制品"},
	{Key: "egg_dairy", Label: "蛋奶"},
	{Key: "staple", Label: "主食"},
	{Key: "dry_goods", Label: "干货"},
	{Key: "seasoning", Label: "调味料"},
	{Key: "sauce", Label: "酱料"},
	{Key: "spice", Label: "香辛料"},
	{Key: "oil", Label: "油脂"},
	{Key: "fruit", Label: "水果"},
	{Key: "nut", Label: "坚果"},
	{Key: "other", Label: "其他"},
}

func main() {
	dbPath := "db/choosy.db"
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Info),
	})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	fmt.Printf("正在初始化食材分类数据: %s\n", dbPath)

	now := time.Now()
	inserted := 0
	skipped := 0

	for _, cat := range categories {
		cat.CreatedAt = now
		cat.UpdatedAt = now

		result := db.Where("key = ?", cat.Key).FirstOrCreate(&cat)
		if result.Error != nil {
			log.Printf("插入 %s 失败: %v", cat.Key, result.Error)
			continue
		}

		if result.RowsAffected > 0 {
			inserted++
			fmt.Printf("  + %s (%s)\n", cat.Label, cat.Key)
		} else {
			skipped++
		}
	}

	fmt.Printf("\n✓ 完成: 新增 %d 条, 跳过 %d 条（已存在）\n", inserted, skipped)
}

