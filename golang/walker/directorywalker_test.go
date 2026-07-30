package walker

import (
	"os"
	"path/filepath"
	"testing"
)

func mkTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("a.txt", "a")
	mk("sub/b.py", "b")
	mk("sub/deep/c", "c")
	mk(".git/config", "x")
	mk("__pycache__/d.pyc", "x")
	mk(".gitignore", "x")
	return root
}

func collect(t *testing.T, root string, excl []string) []*Context {
	t.Helper()
	var got []*Context
	if err := New(root, excl, false).Walk(func(c *Context) error {
		got = append(got, c)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWalkPrunesExcludedSubdirs(t *testing.T) {
	root := mkTree(t)
	for _, c := range collect(t, root, []string{".git", "__pycache__"}) {
		if filepath.Base(c.Path) == ".git" || filepath.Base(c.Path) == "__pycache__" {
			t.Errorf("excluded dir was walked: %s", c.FullPath)
		}
	}
}

func TestWalkYieldsFilesWithContextFields(t *testing.T) {
	root := mkTree(t)
	byName := map[string]*Context{}
	for _, c := range collect(t, root, DefaultExcludeSubdirs) {
		byName[c.Filename] = c
	}

	a, ok := byName["a.txt"]
	if !ok {
		t.Fatal("a.txt not yielded")
	}
	if a.BasePath != root {
		t.Errorf("BasePath: got %q want %q", a.BasePath, root)
	}
	if a.FullPath != filepath.Join(root, "a.txt") {
		t.Errorf("FullPath: got %q", a.FullPath)
	}
	if a.FileType != "txt" || !a.HasFileType {
		t.Errorf("FileType: got %q hasType=%v want \"txt\" true", a.FileType, a.HasFileType)
	}

	// No dot at all => no extension.
	if c := byName["c"]; c == nil {
		t.Fatal("sub/deep/c not yielded")
	} else if c.HasFileType {
		t.Errorf("a name with no dot must have no filetype, got %q", c.FileType)
	}

	// Preserved quirk: split(".") on ".gitignore" is ["", "gitignore"], so the
	// dotfile's own name becomes its extension.
	if g := byName[".gitignore"]; g == nil {
		t.Fatal(".gitignore not yielded")
	} else if !g.HasFileType || g.FileType != "gitignore" {
		t.Errorf("dotfile extension quirk: got %q hasType=%v want \"gitignore\" true", g.FileType, g.HasFileType)
	}
}

func TestWalkIsDeterministicallySorted(t *testing.T) {
	root := mkTree(t)
	first := collect(t, root, DefaultExcludeSubdirs)
	second := collect(t, root, DefaultExcludeSubdirs)
	if len(first) != len(second) {
		t.Fatalf("walk yielded %d then %d files", len(first), len(second))
	}
	for i := range first {
		if first[i].FullPath != second[i].FullPath {
			t.Fatalf("walk order not stable at %d: %q vs %q", i, first[i].FullPath, second[i].FullPath)
		}
	}
}

func TestWalkPropagatesCallbackError(t *testing.T) {
	root := mkTree(t)
	want := os.ErrClosed
	err := New(root, DefaultExcludeSubdirs, false).Walk(func(c *Context) error { return want })
	if err == nil {
		t.Fatal("callback error must propagate")
	}
}

func TestWalkOnSingleFileTarget(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "solo.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := collect(t, p, DefaultExcludeSubdirs)
	if len(got) != 1 || got[0].Filename != "solo.txt" {
		t.Fatalf("a file target must yield itself, got %#v", got)
	}
}

func TestWalkMissingPathErrors(t *testing.T) {
	if err := New(filepath.Join(t.TempDir(), "nope"), nil, false).Walk(func(*Context) error { return nil }); err == nil {
		t.Error("a nonexistent path must error")
	}
}
