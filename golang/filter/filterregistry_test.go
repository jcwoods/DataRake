package filter

import (
	"testing"
	"time"
)

func TestRegisterNamedRejectsDuplicates(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("x"), false)
	if err := r.RegisterNamed("A", f); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterNamed("A", f); err == nil {
		t.Error("duplicate NamedFilter name must be rejected")
	}
}

func TestNamedAndSetNamespacesCollide(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("x"), false)
	if err := r.RegisterNamed("A", f); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterSet("A", []RakeFilter{f}); err == nil {
		t.Error("a FilterSet must not reuse a NamedFilter's name")
	}
	r2 := NewFilterRegistry()
	if err := r2.RegisterSet("B", []RakeFilter{f}); err != nil {
		t.Fatal(err)
	}
	if err := r2.RegisterNamed("B", f); err == nil {
		t.Error("a NamedFilter must not reuse a FilterSet's name")
	}
}

func TestLoadResolvesNamedReference(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("ENCRYPTED"), false)
	r.RegisterNamed("Enc", f)

	got, err := r.Load(map[string]any{"type": "named", "name": "Enc"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != f {
		t.Error("a named reference must resolve to the shared instance")
	}
	if _, err := r.Load(map[string]any{"type": "named", "name": "Nope"}, time.Second); err == nil {
		t.Error("an unknown NamedFilter must error")
	}
	if _, err := r.Load(map[string]any{"type": "named"}, time.Second); err == nil {
		t.Error("a named reference without a name must error")
	}
}

func TestLoadRejectsSetWhereSingleFilterRequired(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("x"), false)
	r.RegisterSet("S", []RakeFilter{f})
	if _, err := r.Load(map[string]any{"type": "set", "name": "S"}, time.Second); err == nil {
		t.Error("a FilterSet must be rejected where a single filter is required")
	}
}

func TestLoadListExpandsSetsInlinePreservingOrder(t *testing.T) {
	r := NewFilterRegistry()
	a, _ := NewLiteralFilter(nil, sp("a"), false)
	b, _ := NewLiteralFilter(nil, sp("b"), false)
	c, _ := NewLiteralFilter(nil, sp("c"), false)
	r.RegisterSet("AB", []RakeFilter{a, b})
	r.RegisterNamed("C", c)

	got, err := r.LoadList([]any{
		map[string]any{"type": "set", "name": "AB"},
		map[string]any{"type": "named", "name": "C"},
		map[string]any{"type": "literal", "value": "d"},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 filters after set expansion, got %d", len(got))
	}
	if got[0] != a || got[1] != b || got[2] != c {
		t.Error("set expansion must preserve order and share instances")
	}
}

func TestLoadListUnknownSetErrors(t *testing.T) {
	r := NewFilterRegistry()
	if _, err := r.LoadList([]any{map[string]any{"type": "set", "name": "Nope"}}, time.Second); err == nil {
		t.Error("an unknown FilterSet must error")
	}
	if _, err := r.LoadList([]any{map[string]any{"type": "set"}}, time.Second); err == nil {
		t.Error("a set reference without a name must error")
	}
}
