package rake

import (
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

func ip(i int) *int { return &i }

func testCtx(line int) *walker.Context {
	return &walker.Context{
		BasePath: "/src", Path: "/src", Filename: "f.txt",
		FullPath: "/src/f.txt", FileType: "txt", HasFileType: true,
		LineNo: ip(line),
	}
}

func mustPattern(t *testing.T, pat string, ctx, key, val *int, ic bool) *Pattern {
	t.Helper()
	p, err := NewPattern(PatternOpts{
		Name: "RakePattern", PType: "test", PDesc: "desc", Severity: "LOW",
		Pattern: pat, CtxGroup: ctx, KeyGroup: key, ValGroup: val,
		IgnoreCase: ic, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewPattern(%q): %v", pat, err)
	}
	return p
}

func TestPatternRequiresContextGroup(t *testing.T) {
	_, err := NewPattern(PatternOpts{
		Name: "R", PType: "t", PDesc: "d", Severity: "LOW",
		Pattern: "(x)", CtxGroup: nil, Timeout: time.Second,
	})
	if err == nil {
		t.Error("a missing context group must be rejected")
	}
}

func TestPatternInvalidRegexErrors(t *testing.T) {
	_, err := NewPattern(PatternOpts{
		Name: "R", PType: "t", PDesc: "d", Severity: "LOW",
		Pattern: "([unclosed", CtxGroup: ip(0), Timeout: time.Second,
	})
	if err == nil {
		t.Error("an invalid pattern must return an error, not exit the process")
	}
}

func TestPatternExtractsGroupsWithPlusOneTranslation(t *testing.T) {
	// Config group k maps to regex group k+1.
	p := mustPattern(t, `((\w+)=(\w+))`, ip(0), ip(1), ip(2), false)
	got, err := p.Match(testCtx(3), "user=jeff\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	m := got[0]
	oc := match.NewOutputConfig(false, false, false)
	if v := m.Context(oc); v == nil || *v != "user=jeff" {
		t.Errorf("context: got %v", v)
	}
	if v := m.Key(); v == nil || *v != "user" {
		t.Errorf("key: got %v", v)
	}
	if v := m.Value(oc); v == nil || *v != "jeff" {
		t.Errorf("value: got %v", v)
	}
	if m.Line() == nil || *m.Line() != 3 {
		t.Errorf("line: got %v want 3", m.Line())
	}
	if m.File() != "f.txt" {
		t.Errorf("file must be relative to basepath: got %q", m.File())
	}
}

func TestPatternOffsetsAreRuneBased(t *testing.T) {
	p := mustPattern(t, `(secret(\d+))`, ip(0), nil, ip(1), false)
	got, err := p.Match(testCtx(1), "héllo 日本 secret42\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	// "héllo 日本 secret" is 15 runes; the digits start at rune 15.
	if off := got[0].ValueOffset(); off == nil || *off != 15 {
		t.Errorf("value offset must be in runes: got %v want 15", off)
	}
	if l := got[0].ValueLength(); l == nil || *l != 2 {
		t.Errorf("value length: got %v want 2", l)
	}
}

func TestPatternMultipleMatchesPerLine(t *testing.T) {
	p := mustPattern(t, `((\w+)=(\w+))`, ip(0), ip(1), ip(2), false)
	got, err := p.Match(testCtx(1), "a=1 b=2 c=3\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(got))
	}
}

func TestPatternNoMatchReturnsEmpty(t *testing.T) {
	p := mustPattern(t, `(zzz)`, ip(0), nil, nil, false)
	got, err := p.Match(testCtx(1), "nothing here\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected no matches, got %d", len(got))
	}
}

func TestPatternIgnorecase(t *testing.T) {
	p := mustPattern(t, `(PASSWORD)`, ip(0), nil, nil, true)
	got, _ := p.Match(testCtx(1), "password\n")
	if len(got) != 1 {
		t.Error("ignorecase must apply")
	}
}

// Python's m.groups(default='') yields "" for groups that did not participate.
func TestMatchGroupsPreservesEmptyForOptionalGroups(t *testing.T) {
	p := mustPattern(t, `((a)(b)?)`, ip(0), nil, nil, false)
	got, _ := p.Match(testCtx(1), "a\n")
	if len(got) != 1 {
		t.Fatal("expected 1 match")
	}
	g := got[0].MatchGroups
	if len(g) != 3 {
		t.Fatalf("expected 3 groups, got %d: %#v", len(g), g)
	}
	if g[0] != "a" || g[1] != "a" || g[2] != "" {
		t.Errorf("groups: got %#v want [a a \"\"]", g)
	}
}

// An unset optional group must stay distinguishable from an empty capture.
func TestUnparticipatingGroupLeavesFieldUnset(t *testing.T) {
	p := mustPattern(t, `((a)(b)?)`, ip(0), nil, ip(2), false)
	got, _ := p.Match(testCtx(1), "a\n")
	if len(got) != 1 {
		t.Fatal("expected 1 match")
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := got[0].Value(oc); v != nil {
		t.Errorf("a non-participating group must leave the value unset, got %q", *v)
	}
}

func TestPatternFilterDropsMatch(t *testing.T) {
	p := mustPattern(t, `((\w+)=(\w+))`, ip(0), ip(1), ip(2), false)
	f, err := filter.NewLiteralFilter(nil, strptr("jeff"), false)
	if err != nil {
		t.Fatal(err)
	}
	p.AddFilter(f)
	got, _ := p.Match(testCtx(1), "user=jeff\n")
	if len(got) != 0 {
		t.Errorf("a matching filter must drop the finding, got %d", len(got))
	}
}

func strptr(s string) *string { return &s }

// SetSelf reproduces Python's dispatch through self.filter().
func TestSelfDispatchIsUsedByMatch(t *testing.T) {
	p := mustPattern(t, `((\w+))`, ip(0), nil, ip(0), false)
	p.SetSelf(rejectAll{})
	got, _ := p.Match(testCtx(1), "anything\n")
	if len(got) != 0 {
		t.Error("Match must route filtering through the installed self")
	}
}

type rejectAll struct{}

func (rejectAll) Filter(*match.RakeMatch) bool { return false }

func TestLoadPatternFromConfig(t *testing.T) {
	cfg := map[string]any{
		"name": "auth token", "pattern": `((Basic|Bearer)\s+(\S{7,}))`,
		"description": "d", "severity": "HIGH",
		"contextgroup": 0, "valgroup": 2, "ignorecase": false,
	}
	p, err := LoadPattern(cfg, filter.NewFilterRegistry(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if p.PType() != "auth token" || p.Severity() != "HIGH" {
		t.Errorf("metadata: %#v", p)
	}
	got, _ := p.Match(testCtx(1), "Authorization: Bearer abcdefghij\n")
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := got[0].Value(oc); v == nil || *v != "abcdefghij" {
		t.Errorf("value: got %v", v)
	}
}

func TestLoadPatternMissingPatternErrors(t *testing.T) {
	_, err := LoadPattern(map[string]any{"name": "x", "contextgroup": 0},
		filter.NewFilterRegistry(), time.Second)
	if err == nil {
		t.Error("a missing pattern must error")
	}
}

func TestLoadPatternFiltersMustBeList(t *testing.T) {
	_, err := LoadPattern(map[string]any{
		"name": "x", "pattern": "(a)", "contextgroup": 0, "filters": "nope",
	}, filter.NewFilterRegistry(), time.Second)
	if err == nil {
		t.Error("a non-list filters key must error")
	}
}

func TestLoadPatternResolvesFilterSets(t *testing.T) {
	reg := filter.NewFilterRegistry()
	f, _ := filter.NewLiteralFilter(nil, strptr("hunter2"), false)
	if err := reg.RegisterSet("Test", []filter.RakeFilter{f}); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPattern(map[string]any{
		"name": "x", "pattern": `((\w+)=(\w+))`, "contextgroup": 0, "valgroup": 2,
		"filters": []any{map[string]any{"type": "set", "name": "Test"}},
	}, reg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := p.Match(testCtx(1), "pw=hunter2\n")
	if len(got) != 0 {
		t.Error("the expanded filter set must suppress the match")
	}
}
