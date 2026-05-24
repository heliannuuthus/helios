package validation

import (
	"fmt"
	"regexp"
)

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{4,32}$`)

// ValidateID 校验资源标识（域/应用/服务 ID）：字母、数字、下划线、连字符，4~32 字符
func ValidateID(kind, id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("%s 仅允许字母、数字、下划线、连字符，4~32 字符", kind)
	}
	return nil
}
