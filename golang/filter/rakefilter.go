// Package filter implements the denylist filters that suppress false-positive
// rake matches. A filter that matches means "discard this finding".
package filter

import (
	"fmt"
	"strings"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

// RakeFilter tests a match. Returning true means the match should be dropped.
// Implementations are read-only after construction, so a single instance is
// safe to share across rakes and across goroutines.
type RakeFilter interface {
	Match(m *match.RakeMatch) bool
	String() string
}

// cfgString reads an optional string. A YAML null, a missing key, or a
// non-string all read as absent.
func cfgString(cfg map[string]any, k string) *string {
	v, ok := cfg[k]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func cfgBool(cfg map[string]any, k string) bool {
	v, ok := cfg[k]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// Load builds a single inline filter. Reference types (named, set) need a
// FilterRegistry to resolve and are rejected here, matching RakeFilter.load.
func Load(cfg map[string]any, timeout time.Duration) (RakeFilter, error) {
	t := cfgString(cfg, "type")
	if t == nil {
		return nil, fmt.Errorf("filter type not specified")
	}

	key := cfgString(cfg, "key")
	val := cfgString(cfg, "value")
	ic := cfgBool(cfg, "ignorecase")

	switch strings.ToLower(*t) {
	case "regex":
		return NewRegexFilter(key, val, ic, timeout)
	case "literal":
		return NewLiteralFilter(key, val, ic)
	case "named", "set":
		name := ""
		if n := cfgString(cfg, "name"); n != nil {
			name = *n
		}
		return nil, fmt.Errorf("filter type %q requires a FilterRegistry to resolve (reference %q)", *t, name)
	default:
		return nil, fmt.Errorf("invalid filter type: %s", *t)
	}
}
