package database

import (
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Option 数据库连接选项
type Option func(*options)

type options struct {
	// 连接池配置
	maxIdleConns    int
	maxOpenConns    int
	connMaxLifetime time.Duration
	connMaxIdleTime time.Duration

	// 日志配置
	logLevel       gormlogger.LogLevel
	logWriter      gormlogger.Writer
	slowThreshold  time.Duration
	ignoreNotFound bool
	colorful       bool
}

// WithMaxIdleConns 设置最大空闲连接数
func WithMaxIdleConns(n int) Option {
	return func(o *options) {
		o.maxIdleConns = n
	}
}

// WithMaxOpenConns 设置最大打开连接数
func WithMaxOpenConns(n int) Option {
	return func(o *options) {
		o.maxOpenConns = n
	}
}

// WithConnMaxLifetime 设置连接最大生存时间
func WithConnMaxLifetime(d time.Duration) Option {
	return func(o *options) {
		o.connMaxLifetime = d
	}
}

// WithConnMaxIdleTime 设置连接最大空闲时间
func WithConnMaxIdleTime(d time.Duration) Option {
	return func(o *options) {
		o.connMaxIdleTime = d
	}
}

// WithLogLevel 设置日志级别
func WithLogLevel(level gormlogger.LogLevel) Option {
	return func(o *options) {
		o.logLevel = level
	}
}

// WithLogWriter 设置日志写入器
func WithLogWriter(w gormlogger.Writer) Option {
	return func(o *options) {
		o.logWriter = w
	}
}

// WithSlowThreshold 设置慢查询阈值
func WithSlowThreshold(d time.Duration) Option {
	return func(o *options) {
		o.slowThreshold = d
	}
}

// WithIgnoreNotFound 设置是否忽略记录未找到错误
func WithIgnoreNotFound(ignore bool) Option {
	return func(o *options) {
		o.ignoreNotFound = ignore
	}
}

// WithColorful 设置是否开启彩色日志
func WithColorful(colorful bool) Option {
	return func(o *options) {
		o.colorful = colorful
	}
}

// defaultOptions 返回默认选项
func defaultOptions() *options {
	return &options{
		maxIdleConns:    10,
		maxOpenConns:    30,
		connMaxLifetime: time.Hour,
		connMaxIdleTime: 30 * time.Minute,
		logLevel:        gormlogger.Error,
		slowThreshold:   200 * time.Millisecond,
		ignoreNotFound:  true,
		colorful:        true,
	}
}

// Connect 连接数据库
// dsn 格式: user:password@tcp(host:port)/dbname?charset=utf8mb4&parseTime=True&loc=Local
func Connect(dsn string, opts ...Option) (*gorm.DB, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	// 配置 GORM 日志
	var gormLog gormlogger.Interface
	if o.logWriter != nil {
		gormLog = gormlogger.New(
			o.logWriter,
			gormlogger.Config{
				SlowThreshold:             o.slowThreshold,
				LogLevel:                  o.logLevel,
				IgnoreRecordNotFoundError: o.ignoreNotFound,
				Colorful:                  o.colorful,
			},
		)
	} else {
		gormLog = gormlogger.Default.LogMode(o.logLevel)
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormLog,
	})
	if err != nil {
		return nil, err
	}

	// 配置连接池
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(o.maxIdleConns)
	sqlDB.SetMaxOpenConns(o.maxOpenConns)
	sqlDB.SetConnMaxLifetime(o.connMaxLifetime)
	if o.connMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(o.connMaxIdleTime)
	}

	return db, nil
}

// MustConnect 连接数据库，失败则 panic
func MustConnect(dsn string, opts ...Option) *gorm.DB {
	db, err := Connect(dsn, opts...)
	if err != nil {
		panic(err)
	}
	return db
}
