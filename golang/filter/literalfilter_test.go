package filter

import (
	"testing"

	"github.com/jcwoods/datarake/golang/match"
)

type fakeRake struct{}

func (fakeRake) PType() string    { return "t" }
func (fakeRake) PDesc() string    { return "d" }
func (fakeRake) Severity() string { return "LOW" }

func sp(s string) *string { return &s }
func line1() *int         { i := 1; return &i }

func withValue(v string) *match.RakeMatch {
	m := match.New(fakeRake{}, "f", line1())
	m.SetValue(v, 0, -1)
	return m
}

func withKey(k string) *match.RakeMatch {
	m := match.New(fakeRake{}, "f", line1())
	m.SetKey(k, 0, -1)
	return m
}

func TestLiteralFilterMatchesValue(t *testing.T) {
	f, err := NewLiteralFilter(nil, sp("password"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(withValue("password")) {
		t.Error("expected match")
	}
	if f.Match(withValue("hunter2")) {
		t.Error("expected no match")
	}
}

func TestLiteralFilterIgnorecase(t *testing.T) {
	f, _ := NewLiteralFilter(nil, sp("PASSWORD"), true)
	if !f.Match(withValue("password")) {
		t.Error("ignorecase must fold both sides")
	}
}

func TestLiteralFilterUnsetValueReturnsFalse(t *testing.T) {
	f, _ := NewLiteralFilter(nil, sp("password"), false)
	m := match.New(fakeRake{}, "f", line1()) // no value set
	if f.Match(m) {
		t.Error("literal filter must return false when the value is unset")
	}
}

func TestLiteralFilterRequiresKeyOrValue(t *testing.T) {
	if _, err := NewLiteralFilter(nil, nil, false); err == nil {
		t.Error("expected an error when neither key nor value is set")
	}
}
