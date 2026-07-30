package writer

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/jcwoods/datarake/golang/match"
)

// JSONWriter streams a single JSON document.
//
// encoding/json is not used because Python's json.dumps differs from it in
// three ways that all show up in output: separator spacing (", " and ": "),
// non-ASCII escaping (ensure_ascii=True), and HTML escaping (Go escapes
// <, > and &; Python does not).
type JSONWriter struct {
	o  Opts
	bw *bufio.Writer

	count       int // secrets written so far
	keysWritten int // top-level keys written so far
}

func NewJSONWriter(o Opts) *JSONWriter {
	return &JSONWriter{o: o, bw: bufio.NewWriter(o.W)}
}

// JSONString renders a Go string exactly as Python's json.dumps would with
// default options: escape the quote and backslash, use short escapes for the
// five control characters that have them, and escape everything outside
// printable ASCII (0x20-0x7e) as \uXXXX, with surrogate pairs above the BMP.
func JSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')

	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
				continue
			}
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
				continue
			}
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}

	b.WriteByte('"')
	return b.String()
}

// jsonNumOrNull renders an optional integer.
func jsonNumOrNull(p *int) string {
	if p == nil {
		return "null"
	}
	return strconv.Itoa(*p)
}

// jsonStrOrNull renders an optional string.
func jsonStrOrNull(p *string) string {
	if p == nil {
		return "null"
	}
	return JSONString(*p)
}

func (w *JSONWriter) InitOutput() error {
	w.count = 0
	w.keysWritten = 0
	_, err := w.bw.WriteString("{")
	return err
}

func (w *JSONWriter) InitSecrets() error {
	if w.o.Quiet {
		return nil
	}
	w.keysWritten++
	_, err := w.bw.WriteString(`"secrets": [`)
	return err
}

// WriteSecret emits one finding. Keys are written in the insertion order of
// RakeMatch.asdict: path, line, type, description, severity, context, value.
func (w *JSONWriter) WriteSecret(m *match.RakeMatch) error {
	if w.o.Quiet {
		return nil
	}
	if w.count > 0 {
		if _, err := w.bw.WriteString(","); err != nil {
			return err
		}
	}

	var b strings.Builder
	b.WriteString("{")
	b.WriteString(`"path": ` + JSONString(m.File()))

	line := "null"
	if m.Line() != nil {
		line = strconv.Itoa(*m.Line())
	}
	b.WriteString(`, "line": ` + line)
	b.WriteString(`, "type": ` + JSONString(m.Label()))
	b.WriteString(`, "description": ` + JSONString(m.Description()))
	b.WriteString(`, "severity": ` + JSONString(m.Severity()))

	if !w.o.Output.DisableContext() {
		b.WriteString(`, "context": {"value": ` + jsonStrOrNull(m.Context(w.o.Output)))
		b.WriteString(`, "offset": ` + jsonNumOrNull(m.ContextOffset()))
		b.WriteString(`, "length": ` + jsonNumOrNull(m.ContextLength()) + "}")
	}

	if !w.o.Output.DisableValue() {
		b.WriteString(`, "value": {"value": ` + jsonStrOrNull(m.Value(w.o.Output)))
		b.WriteString(`, "offset": ` + jsonNumOrNull(m.ValueOffset()))
		b.WriteString(`, "length": ` + jsonNumOrNull(m.ValueLength()) + "}")
	}

	b.WriteString("}")

	if _, err := w.bw.WriteString(b.String()); err != nil {
		return err
	}
	w.count++
	return nil
}

func (w *JSONWriter) EndSecrets() error {
	if w.o.Quiet {
		return nil
	}
	_, err := w.bw.WriteString("]")
	return err
}

func (w *JSONWriter) InitSummary() error {
	if !w.o.Summary {
		return nil
	}
	if w.keysWritten > 0 {
		if _, err := w.bw.WriteString(","); err != nil {
			return err
		}
	}
	w.keysWritten++
	_, err := w.bw.WriteString(`"summary": `)
	return err
}

// WriteSummary emits the totals. Key order is the insertion order of the
// totals dict in main(): files, lines, hits, bytes.
func (w *JSONWriter) WriteSummary(s Summary) error {
	if !w.o.Summary {
		return nil
	}
	_, err := fmt.Fprintf(w.bw,
		`{"files": %d, "lines": %d, "hits": %d, "bytes": %d}`,
		s.Files, s.Lines, s.Hits, s.Bytes)
	return err
}

func (w *JSONWriter) EndSummary() error { return nil }

func (w *JSONWriter) EndOutput() error {
	if _, err := w.bw.WriteString("}\n"); err != nil {
		return err
	}
	return w.bw.Flush()
}
