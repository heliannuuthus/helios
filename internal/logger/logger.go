package logger

import (
	"github.com/heliannuuthus/helios/internal/config"
	pkglogger "github.com/heliannuuthus/helios/pkg/logger"
	"go.uber.org/zap"
)

var (
	Log   *zap.Logger   = pkglogger.Log
	Sugar *zap.SugaredLogger = pkglogger.Sugar
)

// Init 初始化日志（包装 pkg/logger）
func Init() {
	pkglogger.InitWithConfig(pkglogger.Config{
		Format: config.GetString("log.format"),
		Level:  config.GetString("log.level"),
		Debug:  config.GetBool("app.debug"),
	})
	Log = pkglogger.Log
	Sugar = pkglogger.Sugar
}

// 重新导出 pkg/logger 的所有函数和类型
var (
	Sync       = pkglogger.Sync
	Debug      = pkglogger.Debug
	Info       = pkglogger.Info
	Warn       = pkglogger.Warn
	Error      = pkglogger.Error
	Fatal      = pkglogger.Fatal
	Debugf     = pkglogger.Debugf
	Infof      = pkglogger.Infof
	Warnf      = pkglogger.Warnf
	Errorf     = pkglogger.Errorf
	Fatalf     = pkglogger.Fatalf
	WithFields = pkglogger.WithFields
	GormWriter = pkglogger.GormWriter
	S          = pkglogger.S
	L          = pkglogger.L
	Exit       = pkglogger.Exit
)

// GormLogWriter GORM 日志写入器
type GormLogWriter = pkglogger.GormLogWriter
