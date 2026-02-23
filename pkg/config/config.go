package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

const (
	// 配置文件名（位于 config/ 目录）
	ConfigFile       = "config"
	ZweiConfigFile   = "zwei"
	HermesConfigFile = "hermes"
	AegisConfigFile  = "aegis"
	IrisConfigFile   = "iris"
	ChaosConfigFile  = "chaos"

	// 配置名称
	ConfigName       = "helios"
	ZweiConfigName   = "zwei"
	HermesConfigName = "hermes"
	AegisConfigName  = "aegis"
	IrisConfigName   = "iris"
	ChaosConfigName  = "chaos"
)

// Cfg 配置实例包装器
type Cfg struct {
	*viper.Viper
	name     string
	snapshot map[string]any
}

// 配置单例
var (
	cfg       *Cfg // 通用配置
	zweiCfg   *Cfg
	hermesCfg *Cfg
	aegisCfg  *Cfg
	irisCfg   *Cfg
	chaosCfg  *Cfg
)

// newCfg 创建新的配置实例
func newCfg(name, configFile string) *Cfg {
	v := viper.New()

	v.SetConfigName(configFile)
	v.SetConfigType("toml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	// 设置环境变量前缀和自动绑定
	prefix := strings.ToUpper(name)
	v.SetEnvPrefix(prefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundErr viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundErr) {
			panic(fmt.Sprintf("[%s] 读取配置文件失败: %s", name, err.Error()))
		}
		panic(fmt.Sprintf("[%s] 配置文件 %s.toml 不存在", name, configFile))
	}

	cfg := &Cfg{
		Viper:    v,
		name:     name,
		snapshot: v.AllSettings(),
	}

	// 启用热更新
	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		newSettings := v.AllSettings()
		changes := detectChanges("", cfg.snapshot, newSettings)

		if len(changes) > 0 {
			fmt.Printf("[%s] 配置热更新: %s\n", name, e.Name)
			for _, change := range changes {
				fmt.Printf("[%s]   %s (已更新)\n", name, change.Key)
			}
		}

		cfg.snapshot = newSettings
	})

	fmt.Printf("[%s] 配置加载成功: %s\n", name, v.ConfigFileUsed())
	return cfg
}

// Change 配置变更
type Change struct {
	Key      string
	OldValue any
	NewValue any
}

// detectChanges 检测配置变更
func detectChanges(prefix string, old, new map[string]any) []Change {
	var changes []Change

	for k, newVal := range new {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		oldVal, exists := old[k]
		if !exists {
			changes = append(changes, Change{Key: key, OldValue: nil, NewValue: newVal})
			continue
		}

		if newMap, ok := newVal.(map[string]any); ok {
			if oldMap, ok := oldVal.(map[string]any); ok {
				changes = append(changes, detectChanges(key, oldMap, newMap)...)
				continue
			}
		}

		if !reflect.DeepEqual(oldVal, newVal) {
			changes = append(changes, Change{Key: key, OldValue: oldVal, NewValue: newVal})
		}
	}

	for k, oldVal := range old {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		if _, exists := new[k]; !exists {
			changes = append(changes, Change{Key: key, OldValue: oldVal, NewValue: nil})
		}
	}

	return changes
}

// Load 加载所有配置
func Load() {
	LoadConfig()
	LoadZwei()
	LoadHermes()
	LoadAegis()
	LoadIris()
	LoadChaos()
}

// LoadConfig 加载通用配置
func LoadConfig() {
	if cfg != nil {
		return
	}
	cfg = newCfg(ConfigName, ConfigFile)
}

// LoadZwei 加载 Zwei 配置
func LoadZwei() {
	if zweiCfg != nil {
		return
	}
	zweiCfg = newCfg(ZweiConfigName, ZweiConfigFile)
}

// LoadHermes 加载 Hermes 配置
func LoadHermes() {
	if hermesCfg != nil {
		return
	}
	hermesCfg = newCfg(HermesConfigName, HermesConfigFile)
}

// LoadAegis 加载 Aegis 配置
func LoadAegis() {
	if aegisCfg != nil {
		return
	}
	aegisCfg = newCfg(AegisConfigName, AegisConfigFile)
}

// LoadIris 加载 Iris 配置
func LoadIris() {
	if irisCfg != nil {
		return
	}
	irisCfg = newCfg(IrisConfigName, IrisConfigFile)
}

// LoadChaos 加载 Chaos 配置
func LoadChaos() {
	if chaosCfg != nil {
		return
	}
	chaosCfg = newCfg(ChaosConfigName, ChaosConfigFile)
}

// Zwei 返回 Zwei 配置单例
func Zwei() *Cfg {
	if zweiCfg == nil {
		LoadZwei()
	}
	return zweiCfg
}

// Hermes 返回 Hermes 配置单例
func Hermes() *Cfg {
	if hermesCfg == nil {
		LoadHermes()
	}
	return hermesCfg
}

// Aegis 返回 Aegis 配置单例
func Aegis() *Cfg {
	if aegisCfg == nil {
		LoadAegis()
	}
	return aegisCfg
}

// Iris 返回 Iris 配置单例
func Iris() *Cfg {
	if irisCfg == nil {
		LoadIris()
	}
	return irisCfg
}

// Chaos 返回 Chaos 配置单例
func Chaos() *Cfg {
	if chaosCfg == nil {
		LoadChaos()
	}
	return chaosCfg
}

// Config 返回通用配置单例
func Config() *Cfg {
	if cfg == nil {
		LoadConfig()
	}
	return cfg
}

// ==================== 通用配置访问函数 ====================

// GetAppName 获取应用名称
func GetAppName() string {
	return Config().GetString("app.name")
}

// GetAppVersion 获取应用版本
func GetAppVersion() string {
	return Config().GetString("app.version")
}

// IsDebug 是否调试模式
func IsDebug() bool {
	return Config().GetBool("app.debug")
}

// GetEnv 获取环境标识
func GetEnv() string {
	return Config().GetString("app.env")
}

// GetServerHost 获取服务监听地址
func GetServerHost() string {
	host := Config().GetString("server.host")
	if host == "" {
		return "0.0.0.0"
	}
	return host
}

// GetServerPort 获取服务监听端口
func GetServerPort() int {
	port := Config().GetInt("server.port")
	if port == 0 {
		return 18000
	}
	return port
}

// GetLogLevel 获取日志级别
func GetLogLevel() string {
	level := Config().GetString("log.level")
	if level == "" {
		return "info"
	}
	return level
}

// GetLogFormat 获取日志格式
func GetLogFormat() string {
	format := Config().GetString("log.format")
	if format == "" {
		return "console"
	}
	return format
}

// IsModuleEnabled 检查模块是否启用
func IsModuleEnabled(module string) bool {
	return Config().GetBool("modules." + module)
}

// GetRedisURL 获取 Redis URL
func GetRedisURL() string {
	return Config().GetString("redis.url")
}

// ==================== R2 (Cloudflare) 配置访问函数 ====================

// GetR2AccountID 获取 Cloudflare Account ID
func GetR2AccountID() string {
	return Config().GetString("r2.account-id")
}

// GetR2AccessKeyID 获取 R2 Access Key ID
func GetR2AccessKeyID() string {
	return Config().GetString("r2.access-key-id")
}

// GetR2AccessKeySecret 获取 R2 Access Key Secret
func GetR2AccessKeySecret() string {
	return Config().GetString("r2.access-key-secret")
}

// GetR2Bucket 获取 R2 Bucket 名称
func GetR2Bucket() string {
	return Config().GetString("r2.bucket")
}

// GetR2Domain 获取 R2 自定义域名
func GetR2Domain() string {
	return Config().GetString("r2.domain")
}

// Name 返回配置名称
func (c *Cfg) Name() string {
	return c.name
}

// GetDuration 获取 Duration 类型配置（覆盖 viper 的方法以支持热更新）
func (c *Cfg) GetDuration(key string) time.Duration {
	return c.Viper.GetDuration(key)
}
