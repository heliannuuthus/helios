package expr

import (
	"testing"
)

func TestParse_SingleIdent(t *testing.T) {
	node, err := Parse("admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !Eval(node, func(s string) bool { return s == "admin" }) {
		t.Fatal("expected true")
	}
}

func TestParse_And(t *testing.T) {
	node, err := Parse("admin && active")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if Eval(node, func(s string) bool { return s == "admin" }) {
		t.Fatal("should fail when active is false")
	}
	if !Eval(node, func(s string) bool { return true }) {
		t.Fatal("should pass when both true")
	}
}

func TestParse_Or(t *testing.T) {
	node, err := Parse("admin || editor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !Eval(node, func(s string) bool { return s == "editor" }) {
		t.Fatal("should pass when editor is true")
	}
	if Eval(node, func(s string) bool { return false }) {
		t.Fatal("should fail when both false")
	}
}

func TestParse_Not(t *testing.T) {
	node, err := Parse("!banned")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !Eval(node, func(s string) bool { return false }) {
		t.Fatal("should pass when banned is false")
	}
	if Eval(node, func(s string) bool { return s == "banned" }) {
		t.Fatal("should fail when banned is true")
	}
}

func TestParse_Complex(t *testing.T) {
	node, err := Parse("(admin || editor) && !banned")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	roles := map[string]bool{"admin": true, "banned": false}
	if !Eval(node, func(s string) bool { return roles[s] }) {
		t.Fatal("admin && !banned should pass")
	}

	roles["banned"] = true
	if Eval(node, func(s string) bool { return roles[s] }) {
		t.Fatal("admin && banned should fail")
	}

	roles = map[string]bool{"editor": true, "banned": false}
	if !Eval(node, func(s string) bool { return roles[s] }) {
		t.Fatal("editor && !banned should pass")
	}
}

func TestParse_ColonIdent(t *testing.T) {
	node, err := Parse("staff:admin && !staff:banned")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idents := Idents(node)
	if len(idents) != 2 || idents[0] != "staff:admin" || idents[1] != "staff:banned" {
		t.Fatalf("unexpected idents: %v", idents)
	}
}

func TestParse_Precedence(t *testing.T) {
	node, err := Parse("a || b && c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// && binds tighter: a || (b && c)
	// a=true → true regardless of b,c
	if !Eval(node, func(s string) bool { return s == "a" }) {
		t.Fatal("a should short-circuit or")
	}
	// a=false, b=true, c=false → false (b && c = false)
	if Eval(node, func(s string) bool { return s == "b" }) {
		t.Fatal("b alone should not pass")
	}
	// a=false, b=true, c=true → true
	if !Eval(node, func(s string) bool { return s == "b" || s == "c" }) {
		t.Fatal("b && c should pass via or")
	}
}

func TestParse_Error(t *testing.T) {
	cases := []string{
		"",
		"&&",
		"admin &&",
		"admin ||",
		"(admin",
		"admin)",
	}
	for _, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestIdents_Dedup(t *testing.T) {
	node, err := Parse("admin && admin || admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idents := Idents(node)
	if len(idents) != 1 || idents[0] != "admin" {
		t.Fatalf("expected deduped idents, got: %v", idents)
	}
}
