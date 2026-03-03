// Package expr 提供布尔表达式解析器，支持 &&（与）、||（或）、!（非）和括号分组。
//
// 表达式语法：
//
//	expr     = or_expr
//	or_expr  = and_expr ( "||" and_expr )*
//	and_expr = unary ( "&&" unary )*
//	unary    = "!" unary | primary
//	primary  = "(" or_expr ")" | IDENT
//
// 示例：
//
//	"admin"                        → 单个标识符
//	"admin || editor"              → admin 或 editor
//	"admin && !guest"              → admin 且非 guest
//	"(admin || editor) && !banned" → (admin 或 editor) 且非 banned
package expr

import (
	"fmt"
	"strings"
	"unicode"
)

// Node 表达式 AST 节点。
type Node interface {
	node()
	String() string
}

type identNode struct{ name string }
type notNode struct{ operand Node }
type andNode struct{ operands []Node }
type orNode struct{ operands []Node }

func (*identNode) node() {}
func (*notNode) node()   {}
func (*andNode) node()   {}
func (*orNode) node()    {}

func (n *identNode) String() string { return n.name }
func (n *notNode) String() string   { return "!" + n.operand.String() }
func (n *andNode) String() string {
	parts := make([]string, len(n.operands))
	for i, op := range n.operands {
		parts[i] = op.String()
	}
	return "(" + strings.Join(parts, " && ") + ")"
}
func (n *orNode) String() string {
	parts := make([]string, len(n.operands))
	for i, op := range n.operands {
		parts[i] = op.String()
	}
	return "(" + strings.Join(parts, " || ") + ")"
}

// Idents 返回表达式中所有标识符（去重、保序）。
func Idents(n Node) []string {
	seen := make(map[string]struct{})
	var result []string
	collectIdents(n, seen, &result)
	return result
}

func collectIdents(n Node, seen map[string]struct{}, result *[]string) {
	switch v := n.(type) {
	case *identNode:
		if _, ok := seen[v.name]; !ok {
			seen[v.name] = struct{}{}
			*result = append(*result, v.name)
		}
	case *notNode:
		collectIdents(v.operand, seen, result)
	case *andNode:
		for _, op := range v.operands {
			collectIdents(op, seen, result)
		}
	case *orNode:
		for _, op := range v.operands {
			collectIdents(op, seen, result)
		}
	}
}

// Eval 对 AST 求值。resolver 将标识符映射为 bool（true=通过）。
func Eval(n Node, resolver func(ident string) bool) bool {
	switch v := n.(type) {
	case *identNode:
		return resolver(v.name)
	case *notNode:
		return !Eval(v.operand, resolver)
	case *andNode:
		for _, op := range v.operands {
			if !Eval(op, resolver) {
				return false
			}
		}
		return true
	case *orNode:
		for _, op := range v.operands {
			if Eval(op, resolver) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// ---------- Parser ----------

// Parse 解析布尔表达式字符串为 AST。
func Parse(expression string) (Node, error) {
	p := &parser{input: expression, pos: 0}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos < len(p.input) {
		return nil, fmt.Errorf("unexpected character %q at position %d", p.input[p.pos], p.pos)
	}
	return node, nil
}

type parser struct {
	input string
	pos   int
}

func (p *parser) skipSpace() {
	for p.pos < len(p.input) && unicode.IsSpace(rune(p.input[p.pos])) {
		p.pos++
	}
}

func (p *parser) peek() byte {
	p.skipSpace()
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	operands := []Node{left}
	for {
		p.skipSpace()
		if p.pos+1 < len(p.input) && p.input[p.pos] == '|' && p.input[p.pos+1] == '|' {
			p.pos += 2
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			operands = append(operands, right)
		} else {
			break
		}
	}

	if len(operands) == 1 {
		return operands[0], nil
	}
	return &orNode{operands: operands}, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	operands := []Node{left}
	for {
		p.skipSpace()
		if p.pos+1 < len(p.input) && p.input[p.pos] == '&' && p.input[p.pos+1] == '&' {
			p.pos += 2
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			operands = append(operands, right)
		} else {
			break
		}
	}

	if len(operands) == 1 {
		return operands[0], nil
	}
	return &andNode{operands: operands}, nil
}

func (p *parser) parseUnary() (Node, error) {
	if p.peek() == '!' {
		p.pos++
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &notNode{operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	if p.peek() == '(' {
		p.pos++
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ')' {
			return nil, fmt.Errorf("expected ')' at position %d", p.pos)
		}
		p.pos++
		return node, nil
	}
	return p.parseIdent()
}

func (p *parser) parseIdent() (Node, error) {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.input) && isIdentChar(p.input[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("unexpected end of expression")
		}
		return nil, fmt.Errorf("unexpected character %q at position %d", p.input[p.pos], p.pos)
	}
	return &identNode{name: p.input[start:p.pos]}, nil
}

func isIdentChar(c byte) bool {
	return c == '_' || c == '-' || c == ':' || c == '.' || c == '*' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
