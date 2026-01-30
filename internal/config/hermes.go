package config

// Hermes 配置 Key 常量
const (
	// App 配置
	HermesAppDebug   = "app.debug"
	HermesAppName    = "app.name"
	HermesAppVersion = "app.version"
	HermesAppEnv     = "app.env"

	// Server 配置
	HermesServerHost = "server.host"
	HermesServerPort = "server.port"

	// Database 配置
	HermesDBHost     = "database.host"
	HermesDBPort     = "database.port"
	HermesDBUser     = "database.user"
	HermesDBPassword = "database.password"
	HermesDBName     = "database.name"

	// Database Pool 配置
	HermesDBPoolMaxIdleConns    = "database.pool.max-idle-conns"
	HermesDBPoolMaxOpenConns    = "database.pool.max-open-conns"
	HermesDBPoolConnMaxLifetime = "database.pool.conn-max-lifetime"
	HermesDBPoolConnMaxIdleTime = "database.pool.conn-max-idle-time"

	// Database Timeout 配置
	HermesDBTimeoutConnect = "database.timeout.connect"
	HermesDBTimeoutRead    = "database.timeout.read"
	HermesDBTimeoutWrite   = "database.timeout.write"

	// Log 配置
	HermesLogLevel  = "log.level"
	HermesLogFormat = "log.format"

	// CORS 配置
	HermesCORSOrigins          = "cors.origins"
	HermesCORSAllowCredentials = "cors.allow_credentials"
	HermesCORSAllowMethods     = "cors.allow_methods"
	HermesCORSAllowHeaders     = "cors.allow_headers"

	// Auth Domains 配置（hermes 需要读取域配置来处理身份数据）
	HermesAuthDomains = "auth.domains"
)

// Hermes 配置默认值
const (
	DefaultHermesDBHost             = "localhost"
	DefaultHermesDBPort             = 3306
	DefaultHermesDBUser             = "root"
	DefaultHermesDBPoolMaxIdleConns = 10
	DefaultHermesDBPoolMaxOpenConns = 30
	DefaultHermesDBTimeoutConnect   = "10s"
	DefaultHermesDBTimeoutRead      = "30s"
	DefaultHermesDBTimeoutWrite     = "30s"
	DefaultHermesDBPoolConnMaxLife  = "1h"
	DefaultHermesServerHost         = "0.0.0.0"
	DefaultHermesServerPort         = 18000
)

// GetHermesDomainSignKey 获取域签名密钥
func GetHermesDomainSignKey(domainID string) string {
	return Hermes().GetString(HermesAuthDomains + "." + domainID + ".sign-key")
}

// GetHermesDomainEncryptKey 获取域加密密钥
func GetHermesDomainEncryptKey(domainID string) string {
	return Hermes().GetString(HermesAuthDomains + "." + domainID + ".encrypt-key")
}
