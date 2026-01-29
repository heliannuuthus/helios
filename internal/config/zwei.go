package config

// Zwei 配置 Key 常量
const (
	// App 配置
	ZweiAppDebug   = "app.debug"
	ZweiAppName    = "app.name"
	ZweiAppVersion = "app.version"
	ZweiAppEnv     = "app.env"

	// Server 配置
	ZweiServerHost = "server.host"
	ZweiServerPort = "server.port"

	// Database 配置
	ZweiDBHost     = "database.host"
	ZweiDBPort     = "database.port"
	ZweiDBUser     = "database.user"
	ZweiDBPassword = "database.password"
	ZweiDBName     = "database.name"

	// Database Pool 配置
	ZweiDBPoolMaxIdleConns    = "database.pool.max-idle-conns"
	ZweiDBPoolMaxOpenConns    = "database.pool.max-open-conns"
	ZweiDBPoolConnMaxLifetime = "database.pool.conn-max-lifetime"
	ZweiDBPoolConnMaxIdleTime = "database.pool.conn-max-idle-time"

	// Database Timeout 配置
	ZweiDBTimeoutConnect = "database.timeout.connect"
	ZweiDBTimeoutRead    = "database.timeout.read"
	ZweiDBTimeoutWrite   = "database.timeout.write"

	// Log 配置
	ZweiLogLevel  = "log.level"
	ZweiLogFormat = "log.format"

	// CORS 配置
	ZweiCORSOrigins          = "cors.origins"
	ZweiCORSAllowCredentials = "cors.allow_credentials"
	ZweiCORSAllowMethods     = "cors.allow_methods"
	ZweiCORSAllowHeaders     = "cors.allow_headers"

	// AMap 配置
	ZweiAMapAPIKey = "amap.api-key"

	// OpenRouter 配置
	ZweiOpenRouterAPIKey = "openrouter.api-key"
	ZweiOpenRouterModel  = "openrouter.model"

	// OSS 配置
	ZweiOSSEndpoint        = "oss.endpoint"
	ZweiOSSAccessKeyID     = "oss.access-key-id"
	ZweiOSSAccessKeySecret = "oss.access-key-secret"
	ZweiOSSBucket          = "oss.bucket"
	ZweiOSSDomain          = "oss.domain"
	ZweiOSSRegion          = "oss.region"
	ZweiOSSRoleARN         = "oss.role-arn"
)

// Zwei 配置默认值
const (
	DefaultZweiDBHost             = "localhost"
	DefaultZweiDBPort             = 3306
	DefaultZweiDBUser             = "root"
	DefaultZweiDBPoolMaxIdleConns = 10
	DefaultZweiDBPoolMaxOpenConns = 30
	DefaultZweiDBTimeoutConnect   = "10s"
	DefaultZweiDBTimeoutRead      = "30s"
	DefaultZweiDBTimeoutWrite     = "30s"
	DefaultZweiDBPoolConnMaxLife  = "1h"
	DefaultZweiServerHost         = "0.0.0.0"
	DefaultZweiServerPort         = 18000
)
