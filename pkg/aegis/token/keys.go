package token

import (
	"github.com/heliannuuthus/helios/pkg/aegis/key"
)

// 重新导出 key 包的错误，保持部分兼容
var (
	ErrInvalidKeyFormat = key.ErrInvalidFormat
	ErrKeyNotFound      = key.ErrNotFound
)
