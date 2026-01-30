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

// Cfg 配置实例包装器
type Cfg struct {
	*viper.Viper
	name     string
	snapshot map[string]any
}

// 三个模块的配置单例
var (
	zweiCfg   *Cfg
	hermesCfg *Cfg
	authCfg   *Cfg
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
	LoadZwei()
	LoadHermes()
	LoadAuth()
}

// LoadZwei 加载 Zwei 配置
func LoadZwei() {
	if zweiCfg != nil {
		return
	}
	zweiCfg = newCfg("zwei", "zwei.config")
}

// LoadHermes 加载 Hermes 配置
func LoadHermes() {
	if hermesCfg != nil {
		return
	}
	hermesCfg = newCfg("hermes", "hermes.config")
}

// LoadAuth 加载 Auth 配置
func LoadAuth() {
	if authCfg != nil {
		return
	}
	authCfg = newCfg("auth", "auth.config")
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

// Auth 返回 Auth 配置单例
func Auth() *Cfg {
	if authCfg == nil {
		LoadAuth()
	}
	return authCfg
}

// Name 返回配置名称
func (c *Cfg) Name() string {
	return c.name
}

// GetDuration 获取 Duration 类型配置（覆盖 viper 的方法以支持热更新）
func (c *Cfg) GetDuration(key string) time.Duration {
	return c.Viper.GetDuration(key)
}
