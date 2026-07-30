// Package rakeset applies a collection of rakes to files.
package rakeset

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/walker"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/transform"
)

// encodingSampleSize is how many bytes are sampled for charset detection.
// Detection is accurate on a small sample and we do not want to read entire
// files just to guess.
const encodingSampleSize = 2048

// DefaultExcludeExtensions mirrors RakeSet.DEFAULT_BLACKLIST (common.py:472):
// binary and archive types that are never worth reading. Replaced wholesale by
// DirectoryWalker.ExcludeFileExtensions when the config supplies it.
var DefaultExcludeExtensions = []string{
	".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
	".tiff", ".zip", ".doc", ".docx", ".xls", ".xlsx",
	".pdf", ".tar", ".tgz", ".gz", ".tar.gz",
	".jar", ".war", ".ear", ".class", ".css",
}

// Stats holds per-file or accumulated counters.
type Stats struct {
	Files int64
	Lines int64
	Hits  int64
	Bytes int64
}

func (s *Stats) Add(o Stats) {
	s.Files += o.Files
	s.Lines += o.Lines
	s.Hits += o.Hits
	s.Bytes += o.Bytes
}

// RakeSet is a collection of rakes applied to every file scanned. It is
// read-only once built, so Scan may run on many goroutines at once.
type RakeSet struct {
	contentRakes []rake.ContentRake
	metaRakes    []rake.MetaRake
	verbose      bool
	excludeExts  []string
}

// New builds a RakeSet. A nil excludeExtensions uses DefaultExcludeExtensions;
// an empty non-nil slice excludes nothing.
func New(verbose bool, excludeExtensions []string) *RakeSet {
	exts := DefaultExcludeExtensions
	if excludeExtensions != nil {
		exts = make([]string, 0, len(excludeExtensions))
		for _, e := range excludeExtensions {
			exts = append(exts, NormalizeExtension(e))
		}
	}
	return &RakeSet{verbose: verbose, excludeExts: exts}
}

// NormalizeExtension lowercases and ensures a leading dot, so config entries
// ("doc") and the hardcoded defaults (".doc") compare identically. Multi-part
// entries such as "tar.gz" work because matching is a suffix test.
func NormalizeExtension(e string) string {
	e = strings.ToLower(e)
	if e == "" {
		return ""
	}
	if !strings.HasPrefix(e, ".") {
		e = "." + e
	}
	return e
}

// Add files a rake into the content or metadata list based on its part.
func (rs *RakeSet) Add(r any) error {
	if rs.verbose {
		fmt.Fprintf(os.Stderr, "* Adding new Rake: %v\n", r)
	}
	// ContentRake and MetaRake have disjoint method sets (Match/Filter versus
	// MatchContext), so this switch is unambiguous.
	switch t := r.(type) {
	case rake.MetaRake:
		if t.Part() == rake.PartFileMeta {
			rs.metaRakes = append(rs.metaRakes, t)
			return nil
		}
		return fmt.Errorf("rake %s declares part %q but implements MetaRake", t.Name(), t.Part())
	case rake.ContentRake:
		if t.Part() == rake.PartContent {
			rs.contentRakes = append(rs.contentRakes, t)
			return nil
		}
		return fmt.Errorf("rake %s declares part %q but implements ContentRake", t.Name(), t.Part())
	default:
		return fmt.Errorf("unknown rake type: %T", r)
	}
}

func (rs *RakeSet) ContentCount() int { return len(rs.contentRakes) }
func (rs *RakeSet) MetaCount() int    { return len(rs.metaRakes) }

// MatchContext applies the metadata rakes once per file.
func (rs *RakeSet) MatchContext(ctx *walker.Context) ([]*match.RakeMatch, error) {
	var hits []*match.RakeMatch
	for _, r := range rs.metaRakes {
		// Each rake's MatchContext applies its own filters and returns nil on
		// no-match; we only collect.
		rm, err := r.MatchContext(ctx)
		if err != nil {
			return nil, err
		}
		if rm == nil {
			continue
		}
		hits = append(hits, rm)
	}
	return hits, nil
}

// MatchContent applies the content rakes to one line.
func (rs *RakeSet) MatchContent(ctx *walker.Context, text string) ([]*match.RakeMatch, error) {
	var out []*match.RakeMatch
	for _, r := range rs.contentRakes {
		if rs.verbose {
			fmt.Fprintf(os.Stderr, "using rake: %s at %s: %s", r.Name(), ctx.FullPath, text)
		}
		mset, err := r.Match(ctx, text)
		if err != nil {
			return nil, err
		}
		for _, m := range mset {
			// Python filters again here (common.py:466) even though Match has
			// already applied the chain. Filters are pure and idempotent, so
			// this only costs work; kept so the surviving set is identical.
			if !r.Filter(m) {
				continue
			}
			out = append(out, m)
		}
	}
	return out, nil
}

// excluded reports whether the filename ends with an excluded extension.
// Matching is a case-insensitive suffix test, as at common.py:540.
func (rs *RakeSet) excluded(filename string) (string, bool) {
	lower := strings.ToLower(filename)
	for _, ext := range rs.excludeExts {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(lower, ext) {
			return ext, true
		}
	}
	return "", false
}

// detectEncoding samples the head of a file and guesses its charset. Returns
// "" when the file cannot be read or is empty.
//
// Go's detector is not Python's chardet, so the guess may differ on non-UTF-8
// input. UTF-8 and ASCII are unaffected.
func detectEncoding(fullpath string) string {
	f, err := os.Open(fullpath)
	if err != nil {
		return ""
	}
	defer f.Close()

	buf := make([]byte, encodingSampleSize)
	n, err := io.ReadFull(f, buf)
	if n == 0 {
		return ""
	}
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}

	res, err := chardet.NewTextDetector().DetectBest(buf[:n])
	if err != nil || res == nil {
		return ""
	}
	return res.Charset
}

// decoderFor resolves a charset name to a decoding transformer. An unknown or
// empty name yields nil, meaning "treat the bytes as UTF-8", matching the
// codecs.lookup fallback at common.py:559.
//
// UTF-8 and ASCII deliberately also yield nil. x/text's decoders are lenient:
// they substitute U+FFFD for malformed input, so a chained UTF8Validator would
// never see an invalid byte. Python's codecs are strict and raise
// UnicodeDecodeError. Returning nil routes the raw bytes through the validator,
// which does error, reproducing Python for the overwhelmingly common case.
//
// Single-byte charsets (ISO-8859-1, windows-125x) keep the lenient decoder,
// which is correct: they map all 256 byte values, so Python does not raise for
// them either. The residual divergence is limited to multi-byte non-UTF-8
// charsets such as EUC-JP or Big5, where malformed input yields U+FFFD here but
// raises in Python.
func decoderFor(name string) transform.Transformer {
	if name == "" {
		return nil
	}
	switch strings.ToLower(name) {
	case "utf-8", "utf8", "ascii", "us-ascii":
		return nil
	}
	enc, err := ianaindex.IANA.Encoding(name)
	if err != nil || enc == nil {
		return nil
	}
	return enc.NewDecoder()
}

// lineReader yields lines with Python's universal-newline behavior: \r\n and a
// lone \r both become \n, and each line keeps its trailing \n. That terminator
// matters because $-anchored patterns rely on it.
type lineReader struct {
	r *bufio.Reader
}

func (l *lineReader) readLine() (string, error) {
	var sb strings.Builder
	for {
		r, _, err := l.r.ReadRune()
		if err != nil {
			if sb.Len() > 0 && err == io.EOF {
				// Final line with no terminator.
				return sb.String(), nil
			}
			return "", err
		}

		switch r {
		case '\n':
			sb.WriteByte('\n')
			return sb.String(), nil
		case '\r':
			// Consume a following \n so CRLF counts as one terminator.
			if nr, _, err2 := l.r.ReadRune(); err2 == nil && nr != '\n' {
				_ = l.r.UnreadRune()
			}
			sb.WriteByte('\n')
			return sb.String(), nil
		default:
			sb.WriteRune(r)
		}
	}
}

// Scan scans one file and returns its findings and counters.
//
// It mutates no RakeSet state and writes no output, so it is safe to call
// concurrently. Each Context is produced fresh by the walker and owned by the
// goroutine scanning it, so mutating ctx.LineNo and ctx.Encoding needs no lock.
func (rs *RakeSet) Scan(ctx *walker.Context) ([]*match.RakeMatch, Stats, error) {
	var stats Stats
	var findings []*match.RakeMatch

	if rs.verbose {
		fmt.Fprintf(os.Stderr, "* New context: %s\n", ctx.FullPath)
	}

	if ctx.Path == "" || ctx.Filename == "" {
		if rs.verbose {
			fmt.Fprintln(os.Stderr, "* Context is invalid?")
		}
		return nil, stats, nil
	}

	if ext, skip := rs.excluded(ctx.Filename); skip {
		if rs.verbose {
			fmt.Fprintf(os.Stderr, "* File matches blacklisted extension: %s\n", ext)
		}
		return nil, stats, nil
	}

	if rs.verbose {
		fmt.Fprintln(os.Stderr, "* Applying context Rakes")
	}
	metaHits, err := rs.MatchContext(ctx)
	if err != nil {
		return nil, stats, err
	}
	findings = append(findings, metaHits...)

	enc := detectEncoding(ctx.FullPath)
	if enc == "" {
		enc = "utf-8"
	}
	ctx.Encoding = enc

	f, err := os.Open(ctx.FullPath)
	if err != nil {
		if rs.verbose {
			fmt.Fprintf(os.Stderr, "* Unable to open file: %s\n", ctx.FullPath)
		}
		// Python returns what it has so far; a missing file is not fatal.
		return findings, stats, nil
	}
	defer f.Close()

	// Chain the charset decoder with a UTF-8 validator so undecodable input
	// surfaces as an error, reproducing Python's UnicodeDecodeError rather than
	// silently substituting replacement characters.
	var src io.Reader = f
	if dec := decoderFor(enc); dec != nil {
		src = transform.NewReader(f, transform.Chain(dec, encoding.UTF8Validator))
	} else {
		src = transform.NewReader(f, encoding.UTF8Validator)
	}

	if rs.verbose {
		fmt.Fprintln(os.Stderr, "* Applying content Rakes")
	}

	lr := &lineReader{r: bufio.NewReader(src)}
	lineno := 0
	decodeFailed := false

	for {
		line, err := lr.readLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Cannot process this file due to encoding -- skip the rest.
			// Python discards the count entirely (common.py:590).
			decodeFailed = true
			break
		}

		lineno++
		if rs.verbose && lineno%100 == 0 {
			fmt.Fprintf(os.Stderr, "* %d lines processed (%s)\n", lineno, ctx.FullPath)
		}

		// A fresh int per line: match.New stores this pointer rather than
		// copying it, so a shared &lineno would make every finding in the file
		// report the last line scanned.
		n := lineno
		ctx.LineNo = &n

		hits, err := rs.MatchContent(ctx, line)
		if err != nil {
			return nil, stats, err
		}
		findings = append(findings, hits...)
	}

	stats.Files = 1
	stats.Lines = int64(lineno)
	if decodeFailed {
		stats.Lines = 0
	}
	stats.Hits = int64(len(findings))

	if fi, err := os.Stat(ctx.FullPath); err == nil {
		stats.Bytes = fi.Size()
	}

	return findings, stats, nil
}
