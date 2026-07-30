package rake

import (
	"fmt"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// PatternOpts configures a Pattern. CtxGroup is required; KeyGroup and
// ValGroup are optional. All three are config-level group numbers, which are
// 0-based indexes into a findall tuple and therefore one less than the regex
// group number.
type PatternOpts struct {
	Name     string
	PType    string
	PDesc    string
	Severity string
	Pattern  string

	CtxGroup *int
	KeyGroup *int
	ValGroup *int

	IgnoreCase bool
	Timeout    time.Duration
}

// Pattern is a regex applied to every line of content.
type Pattern struct {
	*Rake

	re       *regexp2.Regexp
	source   string
	ctxGroup *int
	keyGroup *int
	valGroup *int

	filters []filter.RakeFilter

	// self is the outermost Filterer, reproducing Python's dispatch through
	// self.filter(). Subclasses install themselves via SetSelf so that
	// Pattern.Match calls their override rather than this type's.
	self Filterer
}

func NewPattern(o PatternOpts) (*Pattern, error) {
	if o.CtxGroup == nil {
		return nil, fmt.Errorf("no context group given for Rake %q", o.PType)
	}

	name := o.Name
	if name == "" {
		name = "RakePattern"
	}
	base, err := NewRake(name, o.PType, o.PDesc, o.Severity, PartContent)
	if err != nil {
		return nil, err
	}

	opts := regexp2.None
	if o.IgnoreCase {
		opts = regexp2.IgnoreCase
	}
	re, err := regexp2.Compile(o.Pattern, opts)
	if err != nil {
		// Python prints and calls sys.exit(1) here (rakes.py:129). A library
		// returns the error and lets the caller decide.
		return nil, fmt.Errorf("failed to parse pattern %q: %w", o.Pattern, err)
	}
	re.MatchTimeout = o.Timeout

	p := &Pattern{
		Rake: base, re: re, source: o.Pattern,
		ctxGroup: o.CtxGroup, keyGroup: o.KeyGroup, valGroup: o.ValGroup,
	}
	p.self = p
	return p, nil
}

// SetSelf installs the outermost filter implementation. Subclass constructors
// must call this with themselves.
func (p *Pattern) SetSelf(f Filterer) { p.self = f }

func (p *Pattern) AddFilter(f filter.RakeFilter) { p.filters = append(p.filters, f) }

// Source returns the uncompiled pattern, for diagnostics.
func (p *Pattern) Source() string { return p.source }

// setFromGroup copies one regex group into the match via set, translating the
// config-level group number. A group that did not participate is skipped, so
// the field stays unset -- Python's None rather than "".
func setFromGroup(m *regexp2.Match, configGroup *int, set func(string, int, int)) {
	if configGroup == nil {
		return
	}
	g := m.GroupByNumber(*configGroup + 1) // findall-tuple index -> regex group
	if g == nil || len(g.Captures) == 0 {
		return
	}
	// regexp2 indexes in runes, which is what RakeMatch documents.
	set(g.String(), g.Index, g.Length)
}

// Match applies the pattern to one line and returns every surviving match.
func (p *Pattern) Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error) {
	var out []*match.RakeMatch
	relpath := "" // computed lazily, once per line, as Python does
	haveRel := false

	m, err := p.re.FindStringMatch(text)
	if err != nil {
		return nil, fmt.Errorf("rake %s: %w", p.Name(), err)
	}

	for m != nil {
		if !haveRel {
			relpath = RelPath(ctx.BasePath, ctx.FullPath)
			haveRel = true
		}

		rm := match.New(p, relpath, ctx.LineNo)
		setFromGroup(m, p.keyGroup, rm.SetKey)
		setFromGroup(m, p.valGroup, rm.SetValue)
		setFromGroup(m, p.ctxGroup, rm.SetContext)

		// Mirror m.groups(default=''): every group 1..N, "" when absent.
		groups := make([]string, 0, m.GroupCount()-1)
		for i := 1; i < m.GroupCount(); i++ {
			g := m.GroupByNumber(i)
			if g == nil || len(g.Captures) == 0 {
				groups = append(groups, "")
				continue
			}
			groups = append(groups, g.String())
		}
		rm.MatchGroups = groups

		if p.self.Filter(rm) {
			out = append(out, rm)
		}

		if m, err = p.re.FindNextMatch(m); err != nil {
			return nil, fmt.Errorf("rake %s: %w", p.Name(), err)
		}
	}

	return out, nil
}

// Filter applies the denylist. Filters suppress: if any matches, the finding
// is dropped, so this returns false.
func (p *Pattern) Filter(m *match.RakeMatch) bool {
	for _, f := range p.filters {
		if f.Match(m) {
			return false
		}
	}
	return true
}

// Config coercion helpers, shared with FileMeta and ContextPattern.

func cfgInt(cfg map[string]any, k string) *int {
	v, ok := cfg[k]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case int:
		return &n
	case int64:
		i := int(n)
		return &i
	case float64:
		i := int(n)
		return &i
	default:
		return nil
	}
}

func cfgStr(cfg map[string]any, k, def string) string {
	v, ok := cfg[k]
	if !ok || v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func cfgStrPtr(cfg map[string]any, k string) *string {
	v, ok := cfg[k]
	if !ok || v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func cfgBoolean(cfg map[string]any, k string, def bool) bool {
	v, ok := cfg[k]
	if !ok || v == nil {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

// resolveFilters turns a rake's `filters:` config into filter instances,
// expanding FilterSet references through the registry.
func resolveFilters(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration, rakeName string) ([]filter.RakeFilter, error) {
	raw, present := cfg["filters"]
	if !present || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("filters must be a list for Rake %s", rakeName)
	}
	if reg != nil {
		return reg.LoadList(list, timeout)
	}
	out := make([]filter.RakeFilter, 0, len(list))
	for _, e := range list {
		fm, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("filter entries must be mappings for Rake %s", rakeName)
		}
		f, err := filter.Load(fm, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// LoadPattern builds a Pattern from a `type: SimplePattern` rake config.
func LoadPattern(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration) (*Pattern, error) {
	name := cfgStr(cfg, "name", "<-NotNamed->")
	pat := cfgStrPtr(cfg, "pattern")
	if pat == nil {
		return nil, fmt.Errorf("pattern must be given for rake %s", name)
	}

	p, err := NewPattern(PatternOpts{
		Name:     "RakePattern",
		PType:    name,
		PDesc:    cfgStr(cfg, "description", "<-NoDesc->"),
		Severity: cfgStr(cfg, "severity", "LOW"),
		Pattern:  *pat,
		CtxGroup: cfgInt(cfg, "contextgroup"),
		KeyGroup: cfgInt(cfg, "keygroup"),
		ValGroup: cfgInt(cfg, "valgroup"),

		IgnoreCase: cfgBoolean(cfg, "ignorecase", false),
		Timeout:    timeout,
	})
	if err != nil {
		return nil, err
	}

	filters, err := resolveFilters(cfg, reg, timeout, name)
	if err != nil {
		return nil, err
	}
	for _, f := range filters {
		p.AddFilter(f)
	}
	return p, nil
}
