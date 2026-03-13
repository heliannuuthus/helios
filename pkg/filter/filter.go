package filter

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type Op int

const (
	Eq  Op = iota // =
	Neq           // !=
	Gt            // >
	Gte           // >=
	Lt            // <
	Lte           // <=
	Pre           // ~=  (prefix match)
	In            // |   (multi-value)
)

var opSQL = map[Op]string{
	Eq:  "%s = ?",
	Neq: "%s != ?",
	Gt:  "%s > ?",
	Gte: "%s >= ?",
	Lt:  "%s < ?",
	Lte: "%s <= ?",
	Pre: "%s LIKE ?",
	In:  "%s IN (?)",
}

// Whitelist declares which columns accept which operators.
// The first operator is used as the default when the client provides a bare
// "column value" without an explicit operator (not applicable in symbol-based
// parsing, but kept for consistency).
//
//	var serviceFilters = filter.Whitelist{
//	    "service_id": {filter.Eq},
//	    "name":       {filter.Eq, filter.Pre},
//	}
type Whitelist map[string][]Op

// Apply parses the "filter" query-string parameter and appends WHERE clauses
// to db. Only columns present in the whitelist with permitted operators are
// applied; everything else is silently ignored.
//
// Format (URL-decoded):
//
//	filter=col1=val,col2!=val,col3~=val,col4>=val,col5|a|b|c
//
// Multiple conditions are separated by comma. The value of the entire filter
// parameter should be URL-encoded by the client.
//
// Operator symbols (parsed longest-match first):
//
//	~=   prefix match   (LIKE 'val%')
//	!=   not equal
//	>=   greater-equal
//	<=   less-equal
//	>    greater
//	<    less
//	=    equal
//	|    IN (value segments separated by |)
func Apply(db *gorm.DB, raw string, wl Whitelist) *gorm.DB {
	if raw == "" || len(wl) == 0 {
		return db
	}

	for _, expr := range splitExpressions(raw) {
		col, op, val, ok := parseExpression(expr)
		if !ok || val == "" {
			continue
		}
		if !isValidColumn(col) {
			continue
		}
		allowed, exists := wl[col]
		if !exists {
			continue
		}
		if !opAllowed(op, allowed) {
			continue
		}
		db = applyCondition(db, col, op, val)
	}
	return db
}

// splitExpressions splits the raw filter string by comma, but not commas
// inside values shouldn't appear because | is used for multi-value.
func splitExpressions(raw string) []string {
	return strings.Split(raw, ",")
}

// parseExpression parses a single "col<op>val" expression.
//
// Operator detection order matters: two-char operators (~=, !=, >=, <=) must
// be checked before single-char ones (=, >, <). The pipe operator is special:
// "col|a|b|c" means IN with values [a, b, c].
func parseExpression(expr string) (col string, op Op, val string, ok bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", 0, "", false
	}

	// Two-char operators
	for _, pair := range []struct {
		sym string
		op  Op
	}{
		{"~=", Pre},
		{"!=", Neq},
		{">=", Gte},
		{"<=", Lte},
	} {
		if idx := strings.Index(expr, pair.sym); idx > 0 {
			return expr[:idx], pair.op, expr[idx+len(pair.sym):], true
		}
	}

	// Single-char: > < =
	for _, pair := range []struct {
		sym byte
		op  Op
	}{
		{'>', Gt},
		{'<', Lt},
		{'=', Eq},
	} {
		if idx := strings.IndexByte(expr, pair.sym); idx > 0 {
			return expr[:idx], pair.op, expr[idx+1:], true
		}
	}

	// Pipe: col|a|b|c → IN
	if idx := strings.IndexByte(expr, '|'); idx > 0 {
		return expr[:idx], In, expr[idx+1:], true
	}

	return "", 0, "", false
}

func applyCondition(db *gorm.DB, col string, op Op, val string) *gorm.DB {
	tmpl, ok := opSQL[op]
	if !ok {
		return db
	}
	clause := fmt.Sprintf(tmpl, col)

	switch op {
	case Pre:
		return db.Where(clause, val+"%")
	case In:
		return db.Where(clause, strings.Split(val, "|"))
	default:
		return db.Where(clause, val)
	}
}

func isValidColumn(col string) bool {
	if col == "" {
		return false
	}
	for _, c := range col {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func opAllowed(op Op, allowed []Op) bool {
	for _, a := range allowed {
		if a == op {
			return true
		}
	}
	return false
}
