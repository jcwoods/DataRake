package filter

import (
	"fmt"
	"strings"
	"time"
)

// FilterRegistry is the per-config registry of NamedFilters and FilterSets.
// A NamedFilter resolves to one RakeFilter; a FilterSet resolves to a list
// expanded inline wherever it is referenced. Sharing one instance across
// rakes is safe because filters are read-only after construction.
//
// Each config load builds its own registry, so multiple configurations can
// coexist (in tests, for instance) without cross-contamination.
type FilterRegistry struct {
	named map[string]RakeFilter
	sets  map[string][]RakeFilter
}

func NewFilterRegistry() *FilterRegistry {
	return &FilterRegistry{
		named: map[string]RakeFilter{},
		sets:  map[string][]RakeFilter{},
	}
}

func (r *FilterRegistry) RegisterNamed(name string, f RakeFilter) error {
	if _, dup := r.named[name]; dup {
		return fmt.Errorf("duplicate NamedFilter name: %q", name)
	}
	if _, clash := r.sets[name]; clash {
		return fmt.Errorf("name %q is already used by a FilterSet", name)
	}
	r.named[name] = f
	return nil
}

func (r *FilterRegistry) RegisterSet(name string, filters []RakeFilter) error {
	if _, dup := r.sets[name]; dup {
		return fmt.Errorf("duplicate FilterSet name: %q", name)
	}
	if _, clash := r.named[name]; clash {
		return fmt.Errorf("name %q is already used by a NamedFilter", name)
	}
	cp := make([]RakeFilter, len(filters))
	copy(cp, filters)
	r.sets[name] = cp
	return nil
}

// Load resolves a single-filter config, handling `type: named` lookups and
// delegating everything else. A `type: set` here is an error -- use LoadList,
// where sets can expand.
func (r *FilterRegistry) Load(cfg map[string]any, timeout time.Duration) (RakeFilter, error) {
	t := ""
	if s := cfgString(cfg, "type"); s != nil {
		t = strings.ToLower(*s)
	}

	switch t {
	case "named":
		name := cfgString(cfg, "name")
		if name == nil {
			return nil, fmt.Errorf("NamedFilter reference missing 'name'")
		}
		f, ok := r.named[*name]
		if !ok {
			return nil, fmt.Errorf("unknown NamedFilter: %q", *name)
		}
		return f, nil
	case "set":
		name := ""
		if s := cfgString(cfg, "name"); s != nil {
			name = *s
		}
		return nil, fmt.Errorf("FilterSet %q cannot be used where a single filter is required; use it in a filter list instead", name)
	default:
		return Load(cfg, timeout)
	}
}

// LoadList flattens filter-config entries into a filter list. Each entry may
// be an inline filter, a NamedFilter reference, or a FilterSet reference.
// FilterSet references expand inline; order is preserved.
func (r *FilterRegistry) LoadList(cfgs []any, timeout time.Duration) ([]RakeFilter, error) {
	out := make([]RakeFilter, 0, len(cfgs))

	for _, raw := range cfgs {
		cfg, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("filter list entries must be mappings, got %T", raw)
		}

		t := ""
		if s := cfgString(cfg, "type"); s != nil {
			t = strings.ToLower(*s)
		}

		if t == "set" {
			name := cfgString(cfg, "name")
			if name == nil {
				return nil, fmt.Errorf("FilterSet reference missing 'name'")
			}
			set, ok := r.sets[*name]
			if !ok {
				return nil, fmt.Errorf("unknown FilterSet: %q", *name)
			}
			out = append(out, set...)
			continue
		}

		f, err := r.Load(cfg, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}

	return out, nil
}
