package rake

import (
	"fmt"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// FileMetaOpts configures a FileMeta rake. At least one of Path, File or Ext
// must be set. All selects between "every defined pattern must match" and
// "any defined pattern matching is enough".
type FileMetaOpts struct {
	PType    string
	PDesc    string
	Severity string

	Path *string // applied to the directory name
	File *string // applied to the basename
	Ext  *string // applied to the extension

	All        bool
	IgnoreCase bool
	Timeout    time.Duration
}

// FileMeta matches on file metadata rather than content, so it runs once per
// file and returns a single match or nil.
type FileMeta struct {
	*Rake

	pathRe *regexp2.Regexp
	fileRe *regexp2.Regexp
	extRe  *regexp2.Regexp

	allRequired bool
}

func NewFileMeta(o FileMetaOpts) (*FileMeta, error) {
	base, err := NewRake("RakeFileMeta", o.PType, o.PDesc, o.Severity, PartFileMeta)
	if err != nil {
		return nil, err
	}

	opts := regexp2.None
	if o.IgnoreCase {
		opts = regexp2.IgnoreCase
	}
	// Python uses re.match here, anchored at position 0 only.
	compile := func(p *string) (*regexp2.Regexp, error) {
		if p == nil {
			return nil, nil
		}
		re, err := regexp2.Compile(`\A(?:`+*p+`)`, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pattern %q: %w", *p, err)
		}
		re.MatchTimeout = o.Timeout
		return re, nil
	}

	f := &FileMeta{Rake: base, allRequired: o.All}
	if f.pathRe, err = compile(o.Path); err != nil {
		return nil, err
	}
	if f.fileRe, err = compile(o.File); err != nil {
		return nil, err
	}
	if f.extRe, err = compile(o.Ext); err != nil {
		return nil, err
	}
	return f, nil
}

// MatchContext evaluates the defined patterns against the context.
func (f *FileMeta) MatchContext(ctx *walker.Context) (*match.RakeMatch, error) {
	// Report a relative path so filemeta findings look like content findings.
	relfile := ctx.FullPath
	if ctx.BasePath != "" {
		relfile = RelPath(ctx.BasePath, ctx.FullPath)
	}

	// A field that is absent counts as "not matched" rather than "not
	// defined": a file with no extension cannot satisfy an extension pattern.
	var checks []bool
	test := func(re *regexp2.Regexp, subject string, present bool) error {
		if re == nil {
			return nil
		}
		if !present {
			checks = append(checks, false)
			return nil
		}
		ok, err := re.MatchString(subject)
		if err != nil {
			return fmt.Errorf("rake %s: %w", f.Name(), err)
		}
		checks = append(checks, ok)
		return nil
	}

	if err := test(f.pathRe, ctx.Path, ctx.Path != ""); err != nil {
		return nil, err
	}
	if err := test(f.fileRe, ctx.Filename, ctx.Filename != ""); err != nil {
		return nil, err
	}
	if err := test(f.extRe, ctx.FileType, ctx.HasFileType); err != nil {
		return nil, err
	}

	if len(checks) == 0 {
		return nil, nil
	}

	matched := true
	if f.allRequired {
		for _, c := range checks {
			if !c {
				matched = false
				break
			}
		}
	} else {
		matched = false
		for _, c := range checks {
			if c {
				matched = true
				break
			}
		}
	}
	if !matched {
		return nil, nil
	}

	// line is nil: a filemeta finding has no line number.
	rm := match.New(f, relfile, nil)
	if !f.Filter(rm) {
		return nil, nil
	}
	return rm, nil
}

// LoadFileMeta builds a FileMeta from a `type: FileMeta` rake config.
func LoadFileMeta(cfg map[string]any, timeout time.Duration) (*FileMeta, error) {
	name := cfgStrPtr(cfg, "name")
	desc := cfgStrPtr(cfg, "description")
	sev := cfgStrPtr(cfg, "severity")

	if name == nil || desc == nil || sev == nil {
		n := "<unnamed>"
		if name != nil {
			n = *name
		}
		return nil, fmt.Errorf("missing required configuration element(s) for rake: %s", n)
	}

	path := cfgStrPtr(cfg, "path")
	file := cfgStrPtr(cfg, "file")
	ext := cfgStrPtr(cfg, "extension")

	if path == nil && file == nil && ext == nil {
		return nil, fmt.Errorf("at least one of path, file, and extension must be set for rake: %s", *name)
	}

	return NewFileMeta(FileMetaOpts{
		PType: *name, PDesc: *desc, Severity: *sev,
		Path: path, File: file, Ext: ext,
		All:        cfgBoolean(cfg, "all", true),
		IgnoreCase: cfgBoolean(cfg, "ignorecase", false),
		Timeout:    timeout,
	})
}
