package rakeset

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/walker"
)

func ip(i int) *int       { return &i }
func sp(s string) *string { return &s }

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ctxFor(base, full string) *walker.Context {
	dir, name := filepath.Split(full)
	dir = filepath.Clean(dir)
	ext, has := "", false
	for j := len(name) - 1; j >= 0; j-- {
		if name[j] == '.' {
			ext, has = name[j+1:], true
			break
		}
	}
	return &walker.Context{
		BasePath: base, Path: dir, Filename: name, FullPath: full,
		FileType: ext, HasFileType: has,
	}
}

func pwPattern(t *testing.T) *rake.Pattern {
	t.Helper()
	p, err := rake.NewPattern(rake.PatternOpts{
		Name: "RakePattern", PType: "password", PDesc: "d", Severity: "HIGH",
		Pattern: `((\w+)=(\w+))`, CtxGroup: ip(0), KeyGroup: ip(1), ValGroup: ip(2),
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAddDispatchesByPart(t *testing.T) {
	rs := New(false, nil)
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	fm, err := rake.NewFileMeta(rake.FileMetaOpts{
		PType: "ssh", PDesc: "d", Severity: "HIGH",
		File: sp("^id_rsa$"), All: true, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Add(fm); err != nil {
		t.Fatal(err)
	}
	if got := rs.ContentCount(); got != 1 {
		t.Errorf("content rakes: got %d want 1", got)
	}
	if got := rs.MetaCount(); got != 1 {
		t.Errorf("meta rakes: got %d want 1", got)
	}
	if err := rs.Add("not a rake"); err == nil {
		t.Error("an unknown rake type must error")
	}
}

func TestScanCountsLinesWithoutOffByOne(t *testing.T) {
	dir := t.TempDir()
	// Three lines of content.
	p := writeFile(t, dir, "a.txt", "one\ntwo\nthree\n")
	rs := New(false, nil)
	_, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Lines != 3 {
		t.Errorf("lines: got %d want 3 (Python reports 4)", stats.Lines)
	}
	if stats.Files != 1 {
		t.Errorf("files: got %d want 1", stats.Files)
	}
	if stats.Bytes != 14 {
		t.Errorf("bytes: got %d want 14", stats.Bytes)
	}
}

func TestScanFindsContentMatches(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "a.properties", "user=jeff\npassword=hunter2\n")
	rs := New(false, nil)
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(found))
	}
	if stats.Hits != 2 {
		t.Errorf("hits: got %d want 2", stats.Hits)
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := found[1].Value(oc); v == nil || *v != "hunter2" {
		t.Errorf("second finding value: got %v", v)
	}
	if found[1].Line() == nil || *found[1].Line() != 2 {
		t.Errorf("second finding line: got %v want 2", found[1].Line())
	}
}

// Each finding must carry its own line number. A single shared *int would make
// every finding in a file report the last line scanned.
func TestScanLineNumbersArePerFinding(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "multi.properties", "a=1\nb=2\nc=3\nd=4\n")
	rs := New(false, nil)
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, _, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(found))
	}
	for i, m := range found {
		want := i + 1
		if m.Line() == nil || *m.Line() != want {
			t.Errorf("finding %d: line got %v want %d", i, m.Line(), want)
		}
	}
}

func TestScanSkipsBlacklistedExtensions(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "logo.PNG", "password=hunter2\n")
	rs := New(false, nil) // nil => DefaultExcludeExtensions
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 || stats.Files != 0 {
		t.Errorf("a blacklisted extension must be skipped entirely: %d findings, %d files", len(found), stats.Files)
	}
}

func TestScanHonorsConfiguredExtensionList(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "notes.md", "password=hunter2\n")
	// Config-style entries carry no leading dot.
	rs := New(false, []string{"md"})
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, _, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("a configured extension must be excluded, got %d findings", len(found))
	}
	// A .png is no longer excluded once the config replaces the defaults.
	p2 := writeFile(t, dir, "x.png", "password=hunter2\n")
	found2, _, err := rs.Scan(ctxFor(dir, p2))
	if err != nil {
		t.Fatal(err)
	}
	if len(found2) != 1 {
		t.Errorf("the configured list replaces the defaults, got %d findings", len(found2))
	}
}

func TestNormalizeExtension(t *testing.T) {
	for in, want := range map[string]string{
		"doc": ".doc", ".doc": ".doc", "TAR.GZ": ".tar.gz", ".Z": ".z",
	} {
		if got := NormalizeExtension(in); got != want {
			t.Errorf("NormalizeExtension(%q): got %q want %q", in, got, want)
		}
	}
}

func TestScanTranslatesUniversalNewlines(t *testing.T) {
	dir := t.TempDir()
	// CRLF and a lone CR must both become one line each.
	p := writeFile(t, dir, "crlf.txt", "a=1\r\nb=2\rc=3\n")
	rs := New(false, nil)
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Lines != 3 {
		t.Errorf("lines: got %d want 3", stats.Lines)
	}
	if len(found) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(found))
	}
	oc := match.NewOutputConfig(false, false, false)
	// The \r must not survive into the value.
	if v := found[0].Value(oc); v == nil || *v != "1" {
		t.Errorf("CR must be translated out of the line: got %v", v)
	}
}

// $-anchored patterns depend on the line retaining its trailing newline.
func TestScanRetainsTrailingNewlineForDollarAnchors(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "k.pem", "-----BEGIN RSA PRIVATE KEY-----\n")
	pk, err := rake.NewPattern(rake.PatternOpts{
		Name: "RakePattern", PType: "private key", PDesc: "d", Severity: "HIGH",
		Pattern:  `^(-----BEGIN ([A-Z0-9]{2,} )?PRIVATE KEY-----$)`,
		CtxGroup: ip(0), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := New(false, []string{})
	if err := rs.Add(pk); err != nil {
		t.Fatal(err)
	}
	found, _, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("$ must match before the trailing newline, got %d findings", len(found))
	}
}

func TestScanRecordsDetectedEncoding(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "a.txt", "plain ascii content here\n")
	rs := New(false, nil)
	ctx := ctxFor(dir, p)
	if _, _, err := rs.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if ctx.Encoding == "" {
		t.Error("Scan must record the detected encoding on the context")
	}
}

func TestScanUndecodableFileReportsZeroLines(t *testing.T) {
	dir := t.TempDir()
	// Detected as UTF-8 from the sampled head, then invalid UTF-8 past the
	// sample window. Verified against Python: chardet reports utf-8 at 0.99 and
	// the decode raises UnicodeDecodeError on the 0xff, so lineno is zeroed.
	//
	// A short run of arbitrary high bytes would not do: chardet maps those to a
	// single-byte charset that decodes every value, in Python as well as here,
	// so such a file is not undecodable in either language.
	p := filepath.Join(dir, "bin.txt")
	body := append(bytes.Repeat([]byte("héllo 日本 a=1\n"), 120), 0xff, 0xfe, 0xff, 0xfe)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	rs := New(false, []string{})
	_, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	// Python zeroes lineno in the UnicodeDecodeError handler; preserved.
	if stats.Lines != 0 {
		t.Errorf("an undecodable file must report 0 lines, got %d", stats.Lines)
	}
}

// A single-byte charset maps every byte, so such a file decodes cleanly in
// Python too and must be scanned normally rather than treated as undecodable.
func TestScanHighBytesDecodeViaSingleByteCharset(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "latin.txt")
	if err := os.WriteFile(p, []byte{0x41, 0x42, 0xff, 0xfe, 0xff, 0xfe, 0x43}, 0o644); err != nil {
		t.Fatal(err)
	}
	rs := New(false, []string{})
	_, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Lines != 1 {
		t.Errorf("a single-byte-charset file must scan normally, got %d lines", stats.Lines)
	}
}

func TestScanMissingFileIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	rs := New(false, []string{})
	found, stats, err := rs.Scan(ctxFor(dir, filepath.Join(dir, "gone.txt")))
	if err != nil {
		t.Fatalf("a missing file must not be a hard error: %v", err)
	}
	if len(found) != 0 || stats.Files != 0 {
		t.Error("a missing file must yield nothing")
	}
}

func TestScanAppliesFileMetaRakes(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "id_rsa", "not really a key\n")
	fm, err := rake.NewFileMeta(rake.FileMetaOpts{
		PType: "ssh identity file", PDesc: "d", Severity: "HIGH",
		File: sp("^id_(rsa1?|dsa|ecdsa|ed25519)$"), All: false, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := New(false, []string{})
	if err := rs.Add(fm); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 filemeta finding, got %d", len(found))
	}
	if found[0].Line() != nil {
		t.Error("a filemeta finding carries no line")
	}
	if stats.Hits != 1 {
		t.Errorf("hits: got %d want 1", stats.Hits)
	}
}

func TestStatsAdd(t *testing.T) {
	a := Stats{Files: 1, Lines: 2, Hits: 3, Bytes: 4}
	a.Add(Stats{Files: 10, Lines: 20, Hits: 30, Bytes: 40})
	if a != (Stats{Files: 11, Lines: 22, Hits: 33, Bytes: 44}) {
		t.Errorf("Add: got %#v", a)
	}
}

func TestScanIsSafeForConcurrentUse(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 24; i++ {
		paths = append(paths, writeFile(t, dir, string(rune('a'+i))+".properties", "password=hunter2\n"))
	}
	rs := New(false, []string{})
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, len(paths))
	for _, p := range paths {
		go func(p string) {
			found, _, err := rs.Scan(ctxFor(dir, p))
			if err != nil {
				done <- -1
				return
			}
			done <- len(found)
		}(p)
	}
	for range paths {
		if n := <-done; n != 1 {
			t.Fatalf("concurrent scan returned %d findings", n)
		}
	}
}
