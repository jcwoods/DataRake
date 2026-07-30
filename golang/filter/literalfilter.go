package filter

import (
	"fmt"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
)

// LiteralFilter compares the key and/or value for exact equality.
type LiteralFilter struct {
	key        *string
	val        *string
	ignorecase bool
}

func NewLiteralFilter(key, val *string, ignorecase bool) (*LiteralFilter, error) {
	if key == nil && val == nil {
		return nil, fmt.Errorf("one of key or value must be set for literal filter")
	}
	if ignorecase {
		if key != nil {
			k := strings.ToLower(*key)
			key = &k
		}
		if val != nil {
			v := strings.ToLower(*val)
			val = &v
		}
	}
	return &LiteralFilter{key: key, val: val, ignorecase: ignorecase}, nil
}

func (f *LiteralFilter) String() string {
	d := func(p *string) string {
		if p == nil {
			return "None"
		}
		return *p
	}
	return fmt.Sprintf("<RakeLiteralFilter(key=%s, val=%s)>", d(f.key), d(f.val))
}

// Match returns true when every configured side compares equal. Unlike
// RegexFilter, an unset key or value yields false (common.py:759,769).
func (f *LiteralFilter) Match(m *match.RakeMatch) bool {
	// Filters run before output is configured, so read the raw value through
	// the shared non-secure view.
	oc := match.PlainOutput

	if f.val != nil {
		v := m.Value(oc)
		if v == nil {
			return false
		}
		s := *v
		if f.ignorecase {
			s = strings.ToLower(s)
		}
		if s != *f.val {
			return false
		}
	}

	if f.key != nil {
		k := m.Key()
		if k == nil {
			return false
		}
		s := *k
		if f.ignorecase {
			s = strings.ToLower(s)
		}
		if s != *f.key {
			return false
		}
	}

	return true
}
