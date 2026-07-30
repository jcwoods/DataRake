// Package rake implements the issue finders. A Rake is applied either to file
// metadata (once per file) or to content (once per line), producing RakeMatch
// records.
package rake

import (
	"fmt"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// The two places a rake can be applied.
const (
	PartContent  = "content"
	PartFileMeta = "filemeta"
)

// Filterer is implemented by anything that can suppress a match. Pattern holds
// one to reproduce Python's dynamic dispatch through self.filter(): Go
// embedding alone would always call the base implementation.
type Filterer interface {
	Filter(m *match.RakeMatch) bool
}

// ContentRake is applied once per line and returns every match on that line.
type ContentRake interface {
	match.RakeInfo
	Name() string
	Part() string
	Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error)
	Filter(m *match.RakeMatch) bool
}

// MetaRake is applied once per file and returns a single match or nil.
type MetaRake interface {
	match.RakeInfo
	Name() string
	Part() string
	MatchContext(ctx *walker.Context) (*match.RakeMatch, error)
}

// Rake carries the metadata shared by every rake type.
type Rake struct {
	name     string
	ptype    string
	pdesc    string
	severity string
	part     string
}

func NewRake(name, ptype, pdesc, severity, part string) (*Rake, error) {
	if part != PartContent && part != PartFileMeta {
		return nil, fmt.Errorf("invalid part in Rake initializer: %s", part)
	}
	return &Rake{name: name, ptype: ptype, pdesc: pdesc, severity: severity, part: part}, nil
}

func (r *Rake) Name() string     { return r.name }
func (r *Rake) PType() string    { return r.ptype }
func (r *Rake) PDesc() string    { return r.pdesc }
func (r *Rake) Severity() string { return r.severity }
func (r *Rake) Part() string     { return r.part }

func (r *Rake) String() string {
	return fmt.Sprintf("<Rake(%s, %s, %s)>", r.name, r.ptype, r.part)
}

// Filter is the fail-safe default: keep everything. Real filtering is
// implemented per rake type.
func (r *Rake) Filter(m *match.RakeMatch) bool { return true }

// RelPath strips the base path and any leading separators so findings are
// reported relative to the scan root.
//
// Python indexes relpath[0] in a loop and raises IndexError when fullpath
// equals basepath (common.py:121). Reachable when a scan target is a file
// rather than a directory, so the empty case is guarded here instead.
func RelPath(basepath, fullpath string) string {
	rel := fullpath
	if basepath != "" && strings.HasPrefix(fullpath, basepath) {
		rel = fullpath[len(basepath):]
	}
	return strings.TrimLeft(rel, "/")
}
