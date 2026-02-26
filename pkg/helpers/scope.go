package helpers

import "strings"

// ParseScopes 解析 scope 字符串为列表
func ParseScopes(scopeStr string) []string {
	return strings.Fields(scopeStr)
}

// JoinScopes 合并 scope 列表为字符串
func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// ScopeIntersection 计算 scope 交集
func ScopeIntersection(requested, allowed []string) []string {
	allowedSet := make(map[string]bool)
	for _, s := range allowed {
		allowedSet[s] = true
	}

	var result []string
	for _, s := range requested {
		if allowedSet[s] {
			result = append(result, s)
		}
	}
	return result
}

// ContainsScope 检查 scope 列表是否包含某个 scope
func ContainsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
