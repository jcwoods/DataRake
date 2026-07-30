// Package walker enumerates the files to be scanned.
package walker

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultExcludeSubdirs matches DirectoryWalker.__init__ (common.py:31) and is
// used when the config supplies no DirectoryWalker.ExcludeSubdirs.
var DefaultExcludeSubdirs = []string{".svn", ".git"}

// Context describes one file to be scanned. Each Context is created here and
// owned exclusively by the goroutine scanning it, so no locking is needed.
type Context struct {
	BasePath string
	Path     string // directory holding the file
	Filename string // basename
	FullPath string
	FileType string // extension without the dot
	// HasFileType distinguishes "no extension" from "empty extension",
	// which Python represents as None versus "".
	HasFileType bool

	// Encoding is filled in by RakeSet.Scan once detected.
	Encoding string
	// LineNo is the 1-based line currently being scanned, nil outside content
	// scanning.
	LineNo *int
}

// DirectoryWalker recursively enumerates files below a base path, pruning
// excluded directories before descending into them.
type DirectoryWalker struct {
	basePath string
	exclude  map[string]struct{}
	verbose  bool
}

func New(path string, excludeSubdirs []string, verbose bool) *DirectoryWalker {
	if excludeSubdirs == nil {
		excludeSubdirs = DefaultExcludeSubdirs
	}
	ex := make(map[string]struct{}, len(excludeSubdirs))
	for _, d := range excludeSubdirs {
		ex[d] = struct{}{}
	}
	return &DirectoryWalker{basePath: path, exclude: ex, verbose: verbose}
}

// splitExt reproduces the Python rule: split on ".", take the last part only
// when there was at least one dot. ".gitignore" therefore reports the
// extension "gitignore".
func splitExt(name string) (string, bool) {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return "", false
	}
	return parts[len(parts)-1], true
}

// Walk invokes fn once per file, in sorted order. A callback rather than a
// channel keeps cancellation simple: returning an error stops the walk and
// leaves no goroutine behind.
func (w *DirectoryWalker) Walk(fn func(*Context) error) error {
	info, err := os.Stat(w.basePath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", w.basePath, err)
	}

	// A file target yields just itself; its directory becomes the base path so
	// relative reporting stays sensible.
	if !info.IsDir() {
		dir := filepath.Dir(w.basePath)
		return fn(w.newContext(dir, filepath.Base(w.basePath), dir))
	}

	return filepath.WalkDir(w.basePath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if w.verbose {
				fmt.Fprintf(os.Stderr, "* skipping %s: %v\n", p, err)
			}
			// A directory we cannot read is skipped, not fatal.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			// Prune before descending, matching the blacklist applied to
			// os.walk's dirnames at common.py:51.
			if p != w.basePath {
				if _, skip := w.exclude[d.Name()]; skip {
					return fs.SkipDir
				}
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		return fn(w.newContext(filepath.Dir(p), d.Name(), w.basePath))
	})
}

func (w *DirectoryWalker) newContext(dir, name, base string) *Context {
	ext, hasExt := splitExt(name)
	c := &Context{
		BasePath:    base,
		Path:        dir,
		Filename:    name,
		FullPath:    filepath.Join(dir, name),
		FileType:    ext,
		HasFileType: hasExt,
	}
	if w.verbose {
		fmt.Fprintf(os.Stderr, "* New context: %s\n", c.FullPath)
	}
	return c
}
