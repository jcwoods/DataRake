package rake

import (
	"testing"
	"time"
)

func ctxFor(base, dir, name, ext string, hasExt bool) *walkerCtx {
	return newWalkerCtx(base, dir, name, ext, hasExt)
}

func mustFileMeta(t *testing.T, path, file, ext *string, all, ic bool) *FileMeta {
	t.Helper()
	f, err := NewFileMeta(FileMetaOpts{
		PType: "ssh identity file", PDesc: "d", Severity: "HIGH",
		Path: path, File: file, Ext: ext, All: all, IgnoreCase: ic,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFileMetaPartIsFileMeta(t *testing.T) {
	f := mustFileMeta(t, nil, strptr("^id_rsa$"), nil, true, false)
	if f.Part() != PartFileMeta {
		t.Errorf("part: got %q want %q", f.Part(), PartFileMeta)
	}
}

func TestFileMetaMatchesByFilePattern(t *testing.T) {
	f := mustFileMeta(t, nil, strptr("^id_(rsa1?|dsa|ecdsa|ed25519)$"), nil, false, false)
	m, err := f.MatchContext(newWalkerCtx("/src", "/src/.ssh", "id_rsa", "", false))
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected a match for id_rsa")
	}
	m2, _ := f.MatchContext(newWalkerCtx("/src", "/src", "notes.txt", "txt", true))
	if m2 != nil {
		t.Error("expected no match for notes.txt")
	}
}

func TestFileMetaMatchesByExtension(t *testing.T) {
	f := mustFileMeta(t, nil, nil, strptr("^(pem|pfx|p12|p7b|key)$"), false, true)
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "server.PEM", "PEM", true))
	if m == nil {
		t.Error("ignorecase extension match expected")
	}
}

// A file with no extension cannot satisfy an extension pattern; that counts as
// "not matched" rather than "not defined" (rakes.py:56-64).
func TestFileMetaExtensionPatternFailsWhenNoExtension(t *testing.T) {
	f := mustFileMeta(t, nil, nil, strptr("^pem$"), true, false)
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "noext", "", false))
	if m != nil {
		t.Error("a file with no extension must not satisfy an extension pattern")
	}
}

func TestFileMetaAllRequiredSemantics(t *testing.T) {
	// all=true: every defined pattern must match.
	// The file pattern is deliberately not end-anchored: it is applied to the
	// basename including the extension (rakes.py:62), so "^keystore$" could
	// never match "keystore.jks" and the both-match case would be untestable.
	both := mustFileMeta(t, nil, strptr("^keystore"), strptr("^jks$"), true, false)
	if m, _ := both.MatchContext(newWalkerCtx("/src", "/src", "keystore", "", false)); m != nil {
		t.Error("all=true must require the extension pattern to match too")
	}
	if m, _ := both.MatchContext(newWalkerCtx("/src", "/src", "keystore.jks", "jks", true)); m == nil {
		t.Error("all=true must match when both patterns match")
	}

	// all=false: any defined pattern matching is enough.
	any := mustFileMeta(t, nil, strptr("^keystore$"), strptr("^jks$"), false, false)
	if m, _ := any.MatchContext(newWalkerCtx("/src", "/src", "keystore", "", false)); m == nil {
		t.Error("all=false must match on the file pattern alone")
	}
	if m, _ := any.MatchContext(newWalkerCtx("/src", "/src", "other.jks", "jks", true)); m == nil {
		t.Error("all=false must match on the extension alone")
	}
}

func TestFileMetaNoPatternsReturnsNil(t *testing.T) {
	f, err := NewFileMeta(FileMetaOpts{
		PType: "t", PDesc: "d", Severity: "LOW", All: true, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "anything", "", false))
	if m != nil {
		t.Error("with no patterns defined the result must be nil")
	}
}

func TestFileMetaReportsRelativePathAndNoLine(t *testing.T) {
	f := mustFileMeta(t, nil, strptr("^id_rsa$"), nil, false, false)
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src/keys", "id_rsa", "", false))
	if m == nil {
		t.Fatal("expected a match")
	}
	if m.File() != "keys/id_rsa" {
		t.Errorf("file must be relative to basepath: got %q", m.File())
	}
	if m.Line() != nil {
		t.Errorf("a filemeta match carries no line number, got %v", m.Line())
	}
}

func TestFileMetaPathPattern(t *testing.T) {
	f := mustFileMeta(t, strptr(`.*/\.ssh$`), nil, nil, true, false)
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src/.ssh", "config", "", false)); m == nil {
		t.Error("expected the path pattern to match")
	}
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src/etc", "config", "", false)); m != nil {
		t.Error("expected no match outside .ssh")
	}
}

func TestLoadFileMetaRequiresNameDescSeverity(t *testing.T) {
	for _, cfg := range []map[string]any{
		{"description": "d", "severity": "HIGH", "file": "^x$"},
		{"name": "n", "severity": "HIGH", "file": "^x$"},
		{"name": "n", "description": "d", "file": "^x$"},
	} {
		if _, err := LoadFileMeta(cfg, time.Second); err == nil {
			t.Errorf("missing required element must error: %v", cfg)
		}
	}
}

func TestLoadFileMetaRequiresAtLeastOnePattern(t *testing.T) {
	_, err := LoadFileMeta(map[string]any{
		"name": "n", "description": "d", "severity": "HIGH",
		"path": nil, "file": nil, "extension": nil,
	}, time.Second)
	if err == nil {
		t.Error("at least one of path, file, extension must be required")
	}
}

func TestLoadFileMetaBuildsRake(t *testing.T) {
	f, err := LoadFileMeta(map[string]any{
		"name": "netrc file", "description": "d", "severity": "HIGH",
		"file": `\.?netrc$`, "extension": "netrc",
		"all": false, "ignorecase": true,
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if f.PType() != "netrc file" {
		t.Errorf("ptype: %q", f.PType())
	}
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src", ".netrc", "netrc", true)); m == nil {
		t.Error("expected .netrc to match")
	}
}

// `all` defaults to true when the key is absent.
func TestLoadFileMetaAllDefaultsTrue(t *testing.T) {
	f, err := LoadFileMeta(map[string]any{
		"name": "n", "description": "d", "severity": "LOW",
		"file": "^keystore$", "extension": "^jks$",
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "keystore", "", false)); m != nil {
		t.Error("all must default to true, requiring both patterns")
	}
}
