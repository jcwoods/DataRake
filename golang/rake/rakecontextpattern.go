package rake

import (
	"fmt"
	"time"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// ContextPattern binds patterns to file extensions. Each context is a Pattern;
// the rake selects one by the scanned file's extension, falling back to a
// default context when present.
type ContextPattern struct {
	*Rake

	byType     map[string]*Pattern
	def        *Pattern
	hasDefault bool
}

func NewContextPattern(ptype, pdesc, severity string) (*ContextPattern, error) {
	base, err := NewRake("RakeContextPattern", ptype, pdesc, severity, PartContent)
	if err != nil {
		return nil, err
	}
	return &ContextPattern{Rake: base, byType: map[string]*Pattern{}}, nil
}

// AddContext registers a Pattern for one file type. A nil fileType registers
// the default context, which Python keys as None.
func (c *ContextPattern) AddContext(fileType *string, p *Pattern) error {
	if fileType == nil {
		if c.hasDefault {
			return fmt.Errorf("multiple definitions for file type None in rake %s", c.Name())
		}
		c.def, c.hasDefault = p, true
		return nil
	}
	if _, dup := c.byType[*fileType]; dup {
		return fmt.Errorf("multiple definitions for file type %s in rake %s", *fileType, c.Name())
	}
	c.byType[*fileType] = p
	return nil
}

// Match selects the pattern for this file's extension and delegates to it.
func (c *ContextPattern) Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error) {
	var p *Pattern
	if ctx.HasFileType {
		p = c.byType[ctx.FileType]
	}
	if p == nil && c.hasDefault {
		p = c.def
	}
	if p == nil {
		return nil, nil
	}
	return p.Match(ctx, text)
}

// Filter is a no-op at this level: each context Pattern owns its own filters
// and applies them during Match.
func (c *ContextPattern) Filter(m *match.RakeMatch) bool { return true }

// LoadContextPattern builds a ContextPattern from a `type: ContextPattern`
// rake config.
//
// Note: the `skipcontexts:` key that appears on the token rake is read by no
// code, here or in Python. It is left inert deliberately -- honoring it would
// add suppression behavior that has never existed.
func LoadContextPattern(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration) (*ContextPattern, error) {
	name := cfgStr(cfg, "name", "<-None->")
	desc := cfgStr(cfg, "description", "<-None->")
	sev := cfgStr(cfg, "severity", "LOW")

	cp, err := NewContextPattern(name, desc, sev)
	if err != nil {
		return nil, err
	}

	rawContexts, ok := cfg["contexts"].([]any)
	if !ok {
		return cp, nil
	}

	for _, rc := range rawContexts {
		cm, ok := rc.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("contexts entries must be mappings for rake %s", name)
		}

		pat := cfgStrPtr(cm, "pattern")
		if pat == nil {
			return nil, fmt.Errorf("pattern must be given for rake %s context", name)
		}

		p, err := NewPattern(PatternOpts{
			Name:     "RakePattern",
			PType:    name,
			PDesc:    desc,
			Severity: sev,
			Pattern:  *pat,
			CtxGroup: cfgInt(cm, "contextgroup"),
			KeyGroup: cfgInt(cm, "keygroup"),
			ValGroup: cfgInt(cm, "valgroup"),

			IgnoreCase: cfgBoolean(cm, "ignorecase", false),
			Timeout:    timeout,
		})
		if err != nil {
			return nil, err
		}

		filters, err := resolveFilters(cm, reg, timeout, name)
		if err != nil {
			return nil, err
		}
		for _, f := range filters {
			p.AddFilter(f)
		}

		// `context:` may be a scalar, a list, or null (the default context).
		// One Pattern instance is shared across every listed file type.
		for _, ft := range contextFileTypes(cm["context"]) {
			if err := cp.AddContext(ft, p); err != nil {
				return nil, err
			}
		}
	}

	return cp, nil
}

// contextFileTypes normalizes the `context:` value to a list of file types,
// where a nil entry means the default context.
func contextFileTypes(v any) []*string {
	switch t := v.(type) {
	case nil:
		return []*string{nil}
	case string:
		s := t
		return []*string{&s}
	case []any:
		out := make([]*string, 0, len(t))
		for _, e := range t {
			if e == nil {
				out = append(out, nil)
				continue
			}
			if s, ok := e.(string); ok {
				v := s
				out = append(out, &v)
			}
		}
		return out
	default:
		return nil
	}
}
