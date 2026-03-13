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

const maxFilterLength = 500
const maxInValues = 50

var opSQL = map[Op]string{
	Eq:  "%s = ?",
	Neq: "%s != ?",
	Gt:  "%s > ?",
	Gte: "%s >= ?",
	Lt:  "%s < ?",
	Lte: "%s <= ?",
	Pre: "%s LIKE ? ESCAPE '\\'",
	In:  "%s IN (?)",
}

// Whitelist declares which columns accept which operators.
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
// Multiple conditions are separated by comma. Values must not contain
// unencoded commas; use URL-encoding (%2C) if a literal comma is needed.
//
// Operator symbols (matched at the boundary between column name and value):
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
	if raw == "" || len(wl) == 0 || len(raw) > maxFilterLength {
		return db
	}

	for _, expr := range strings.Split(raw, ",") {
		col, op, val, ok := parseExpression(expr)
		if !ok || val == "" {
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

var likeEscaper = strings.NewReplacer("%", "\\%", "_", "\\_")

func applyCondition(db *gorm.DB, col string, op Op, val string) *gorm.DB {
	tmpl, ok := opSQL[op]
	if !ok {
		return db
	}
	clause := fmt.Sprintf(tmpl, col)

	switch op {
	case Pre:
		return db.Where(clause, likeEscaper.Replace(val)+"%")
	case In:
		parts := strings.Split(val, "|")
		filtered := parts[:0]
		for _, p := range parts {
			if p != "" {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) == 0 || len(filtered) > maxInValues {
			return db
		}
		return db.Where(clause, filtered)
	default:
		return db.Where(clause, val)
	}
}

// parseExpression extracts column, operator and value from a single expression.
//
// It first extracts the column name (contiguous [a-z0-9_] characters), then
// matches the operator symbol immediately after the column name. This avoids
// ambiguity when the value itself contains operator characters.
func parseExpression(expr string) (col string, op Op, val string, ok bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", 0, "", false
	}

	i := 0
	for i < len(expr) && isColumnChar(expr[i]) {
		i++
	}
	if i == 0 || i >= len(expr) {
		return "", 0, "", false
	}
	col = expr[:i]
	rest := expr[i:]

	type opDef struct {
		sym string
		op  Op
	}
	for _, def := range []opDef{
		{"~=", Pre}, {"!=", Neq}, {">=", Gte}, {"<=", Lte},
		{">", Gt}, {"<", Lt}, {"=", Eq}, {"|", In},
	} {
		if strings.HasPrefix(rest, def.sym) {
			return col, def.op, rest[len(def.sym):], true
		}
	}
	return "", 0, "", false
}

func isColumnChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}

func opAllowed(op Op, allowed []Op) bool {
	for _, a := range allowed {
		if a == op {
			return true
		}
	}
	return false
}
