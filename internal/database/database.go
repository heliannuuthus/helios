package database

import (
	"os"
	"path/filepath"
	"time"

	"choosy-backend/internal/config"
	"choosy-backend/internal/logger"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var db *gorm.DB

// Init 初始化数据库连接
func Init() *gorm.DB {
	if db != nil {
		return db
	}

	// 确保数据库目录存在
	dbPath := config.GetString("database.url")
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Fatalf("创建数据库目录失败: %v", err)
		}
	}

	// 配置 GORM 日志（只打印错误）
	logLevel := gormlogger.Error

	// 使用 zap 作为 GORM 的日志
	gormLog := gormlogger.New(
		logger.GormWriter(),
		gormlogger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logLevel,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	var err error
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormLog,
	})
	if err != nil {
		logger.Fatalf("连接数据库失败: %v", err)
	}

	logger.Info("数据库连接成功")
	return db
}

// Get 获取数据库连接
func Get() *gorm.DB {
	if db == nil {
		return Init()
	}
	return db
}
