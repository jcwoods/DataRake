package rake

import (
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

func ctxWithType(ext string, hasExt bool, line int) *walker.Context {
	c := newWalkerCtx("/src", "/src", "f", ext, hasExt)
	c.LineNo = ip(line)
	return c
}

func TestContextPatternRoutesByExtension(t *testing.T) {
	cp, err := NewContextPattern("token", "d", "MEDIUM")
	if err != nil {
		t.Fatal(err)
	}
	pyPat := mustPattern(t, `(py_(\w+))`, ip(0), nil, ip(1), false)
	jsPat := mustPattern(t, `(js_(\w+))`, ip(0), nil, ip(1), false)
	if err := cp.AddContext(strptr("py"), pyPat); err != nil {
		t.Fatal(err)
	}
	if err := cp.AddContext(strptr("js"), jsPat); err != nil {
		t.Fatal(err)
	}

	oc := match.NewOutputConfig(false, false, false)

	got, _ := cp.Match(ctxWithType("py", true, 1), "py_secret js_secret\n")
	if len(got) != 1 {
		t.Fatalf("py context: expected 1 match, got %d", len(got))
	}
	if v := got[0].Value(oc); v == nil || *v != "secret" {
		t.Errorf("py context matched the wrong pattern: %v", v)
	}

	got2, _ := cp.Match(ctxWithType("js", true, 1), "py_secret js_secret\n")
	if len(got2) != 1 {
		t.Fatalf("js context: expected 1 match, got %d", len(got2))
	}
}

func TestContextPatternFallsBackToDefault(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	def := mustPattern(t, `(any_(\w+))`, ip(0), nil, ip(1), false)
	if err := cp.AddContext(nil, def); err != nil {
		t.Fatal(err)
	}
	got, _ := cp.Match(ctxWithType("rb", true, 1), "any_thing\n")
	if len(got) != 1 {
		t.Error("an unmatched extension must fall back to the default context")
	}
	// A file with no extension also uses the default.
	got2, _ := cp.Match(ctxWithType("", false, 1), "any_thing\n")
	if len(got2) != 1 {
		t.Error("a file with no extension must use the default context")
	}
}

func TestContextPatternNoDefaultReturnsNothing(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	p := mustPattern(t, `(py_(\w+))`, ip(0), nil, ip(1), false)
	cp.AddContext(strptr("py"), p)
	got, err := cp.Match(ctxWithType("rb", true, 1), "py_secret\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("without a default context an unknown extension must yield nothing, got %d", len(got))
	}
}

func TestContextPatternDuplicateContextErrors(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	p := mustPattern(t, `(a)`, ip(0), nil, nil, false)
	if err := cp.AddContext(strptr("py"), p); err != nil {
		t.Fatal(err)
	}
	if err := cp.AddContext(strptr("py"), p); err == nil {
		t.Error("a duplicate file type must error")
	}
	if err := cp.AddContext(nil, p); err != nil {
		t.Fatal(err)
	}
	if err := cp.AddContext(nil, p); err == nil {
		t.Error("a duplicate default context must error")
	}
}

func TestContextPatternPartIsContent(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	if cp.Part() != PartContent {
		t.Errorf("part: got %q want %q", cp.Part(), PartContent)
	}
}

func TestLoadContextPatternFromConfig(t *testing.T) {
	cfg := map[string]any{
		"name": "token", "description": "possible token", "severity": "MEDIUM",
		"contexts": []any{
			map[string]any{
				"context":      nil,
				"pattern":      `((\w+)=(\w+))`,
				"contextgroup": 0, "keygroup": 1, "valgroup": 2,
				"ignorecase": true,
			},
			map[string]any{
				"context":      []any{"c", "java"},
				"pattern":      `((\w+) := (\w+))`,
				"contextgroup": 0, "keygroup": 1, "valgroup": 2,
			},
		},
	}
	cp, err := LoadContextPattern(cfg, filter.NewFilterRegistry(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cp.PType() != "token" || cp.Severity() != "MEDIUM" {
		t.Errorf("metadata: %#v", cp)
	}

	oc := match.NewOutputConfig(false, false, false)
	got, _ := cp.Match(ctxWithType("txt", true, 1), "tok=abc\n")
	if len(got) != 1 {
		t.Fatalf("default context: expected 1, got %d", len(got))
	}
	if v := got[0].Value(oc); v == nil || *v != "abc" {
		t.Errorf("value: %v", v)
	}

	// A scalar `context:` must work as well as a list.
	got2, _ := cp.Match(ctxWithType("java", true, 1), "tok := abc\n")
	if len(got2) != 1 {
		t.Fatalf("java context: expected 1, got %d", len(got2))
	}
}

func TestLoadContextPatternMissingPatternErrors(t *testing.T) {
	_, err := LoadContextPattern(map[string]any{
		"name": "token", "description": "d", "severity": "LOW",
		"contexts": []any{map[string]any{"context": nil, "contextgroup": 0}},
	}, filter.NewFilterRegistry(), time.Second)
	if err == nil {
		t.Error("a context without a pattern must error")
	}
}

func TestLoadContextPatternSharesOnePatternAcrossFileTypes(t *testing.T) {
	cfg := map[string]any{
		"name": "token", "description": "d", "severity": "LOW",
		"contexts": []any{
			map[string]any{
				"context":      []any{"c", "h", "cpp"},
				"pattern":      `((\w+)=(\w+))`,
				"contextgroup": 0, "valgroup": 2,
			},
		},
	}
	cp, err := LoadContextPattern(cfg, filter.NewFilterRegistry(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{"c", "h", "cpp"} {
		got, _ := cp.Match(ctxWithType(ext, true, 1), "a=b\n")
		if len(got) != 1 {
			t.Errorf("extension %q: expected 1 match, got %d", ext, len(got))
		}
	}
}
