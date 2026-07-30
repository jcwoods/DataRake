package filter

import (
	"fmt"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/match"
)

// RegexFilter applies anchored patterns to the key and/or value.
type RegexFilter struct {
	key *regexp2.Regexp
	val *regexp2.Regexp
	src struct{ key, val string }
}

// NewRegexFilter compiles the patterns. Python uses re.match, which anchors at
// position 0 but not at the end, so each pattern is wrapped in \A(?:...).
func NewRegexFilter(key, val *string, ignorecase bool, timeout time.Duration) (*RegexFilter, error) {
	if key == nil && val == nil {
		return nil, fmt.Errorf("one of key or value must be set for regex filter")
	}

	opts := regexp2.None
	if ignorecase {
		opts = regexp2.IgnoreCase
	}

	f := &RegexFilter{}
	compile := func(p string) (*regexp2.Regexp, error) {
		re, err := regexp2.Compile(`\A(?:`+p+`)`, opts)
		if err != nil {
			return nil, fmt.Errorf("compile filter pattern %q: %w", p, err)
		}
		re.MatchTimeout = timeout
		return re, nil
	}

	if key != nil {
		re, err := compile(*key)
		if err != nil {
			return nil, err
		}
		f.key, f.src.key = re, *key
	}
	if val != nil {
		re, err := compile(*val)
		if err != nil {
			return nil, err
		}
		f.val, f.src.val = re, *val
	}
	return f, nil
}

func (f *RegexFilter) String() string {
	return fmt.Sprintf("<RakeRegexFilter(key=%s, val=%s)>", f.src.key, f.src.val)
}

// Match returns true when every configured pattern matches.
//
// Note the deliberate lack of a nil check on the value and key: Python does
// str(match.value) unconditionally (common.py:813,817), so an unset group is
// tested against the literal text "None". That changes which findings survive,
// so it is reproduced rather than corrected.
func (f *RegexFilter) Match(m *match.RakeMatch) bool {
	oc := match.PlainOutput

	pyStr := func(p *string) string {
		if p == nil {
			return "None"
		}
		return *p
	}

	if f.val != nil {
		ok, err := f.val.MatchString(pyStr(m.Value(oc)))
		if err != nil || !ok {
			return false
		}
	}
	if f.key != nil {
		ok, err := f.key.MatchString(pyStr(m.Key()))
		if err != nil || !ok {
			return false
		}
	}
	return true
}
