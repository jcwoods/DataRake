package filter

import (
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

func TestRegexFilterIsAnchoredAtStart(t *testing.T) {
	// Python uses re.match, which anchors at position 0 but not at the end.
	f, err := NewRegexFilter(nil, sp(`\$[a-z_]+`), true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(withValue("$FOO_BAR trailing")) {
		t.Error("re.match semantics: must match at position 0 without an end anchor")
	}
	if f.Match(withValue("prefix $FOO")) {
		t.Error("re.match semantics: must not match mid-string")
	}
}

// Preserves the str(None) behaviour at common.py:813. RakeRegexFilter does not
// nil-check the value, so an unset value is tested against the text "None".
func TestRegexFilterUnsetValueTestsAgainstLiteralNone(t *testing.T) {
	f, _ := NewRegexFilter(nil, sp(`^.{0,5}$`), false, time.Second)
	m := match.New(fakeRake{}, "f", line1()) // no value set
	if !f.Match(m) {
		t.Error(`unset value must be tested as the literal "None" (4 chars), matching ^.{0,5}$`)
	}
}

func TestRegexFilterKeyPattern(t *testing.T) {
	f, _ := NewRegexFilter(sp(`("?)[Pp]ublicKeyToken(\1)`), nil, false, time.Second)
	if !f.Match(withKey(`"PublicKeyToken"`)) {
		t.Error("backreference in a key filter must work under regexp2")
	}
	if f.Match(withKey("authtoken")) {
		t.Error("expected no match")
	}
}

func TestLoadDispatchesByType(t *testing.T) {
	lf, err := Load(map[string]any{"type": "literal", "value": "ENCRYPTED"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lf.(*LiteralFilter); !ok {
		t.Errorf("type literal must build a LiteralFilter, got %T", lf)
	}
	rf, err := Load(map[string]any{"type": "regex", "value": `^\$[a-z]+$`, "ignorecase": true}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rf.(*RegexFilter); !ok {
		t.Errorf("type regex must build a RegexFilter, got %T", rf)
	}
}

func TestLoadRejectsReferenceTypesAndUnknowns(t *testing.T) {
	for _, tc := range []string{"named", "set", "bogus"} {
		if _, err := Load(map[string]any{"type": tc, "name": "X"}, time.Second); err == nil {
			t.Errorf("type %q must be rejected by Load (needs a FilterRegistry, or is invalid)", tc)
		}
	}
	if _, err := Load(map[string]any{"value": "x"}, time.Second); err == nil {
		t.Error("a missing type must be rejected")
	}
}

// A null key/value in YAML must read as absent, not as the string "null".
func TestNullConfigValuesAreAbsent(t *testing.T) {
	f, err := Load(map[string]any{
		"type": "regex", "key": nil, "value": `^\$[a-z0-9_]+$`, "ignorecase": true,
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(withValue("$foo")) {
		t.Error("expected the value pattern to apply with a null key")
	}
}
