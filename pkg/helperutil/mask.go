// Package helperutil provides utility functions for the application.
package helperutil

import "strings"

// MaskEmail 邮箱脱敏：a**@example.com
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	local := parts[0]
	if len(local) <= 1 {
		return local + "**@" + parts[1]
	}
	return string(local[0]) + "**@" + parts[1]
}

// MaskPhone 手机号脱敏：138****1234
func MaskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 7 {
		return phone
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}
