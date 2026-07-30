package writer

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
)

// CSVWriter emits findings as CSV.
//
// encoding/csv is deliberately not used: it quotes any field with leading or
// trailing whitespace, which Python's csv.writer does not, and a context can
// legitimately begin with a space.
type CSVWriter struct {
	o  Opts
	bw *bufio.Writer
}

func NewCSVWriter(o Opts) *CSVWriter {
	return &CSVWriter{o: o, bw: bufio.NewWriter(o.W)}
}

// CSVField applies Python's QUOTE_MINIMAL: quote only when the field contains
// the delimiter, a double quote, CR or LF, doubling embedded quotes.
func CSVField(s string) string {
	if strings.ContainsAny(s, ",\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// writeRow emits one CRLF-terminated record.
func (w *CSVWriter) writeRow(fields []string) error {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = CSVField(f)
	}
	_, err := w.bw.WriteString(strings.Join(out, ",") + "\r\n")
	return err
}

func (w *CSVWriter) InitOutput() error { return nil }

func (w *CSVWriter) InitSecrets() error {
	if w.o.Quiet {
		return nil
	}
	return w.writeRow(w.o.Output.Header())
}

func (w *CSVWriter) WriteSecret(m *match.RakeMatch) error {
	if w.o.Quiet {
		return nil
	}
	return w.writeRow(m.AsRecord(w.o.Output))
}

func (w *CSVWriter) EndSecrets() error { return w.bw.Flush() }

func (w *CSVWriter) InitSummary() error { return nil }

// WriteSummary emits plain "key: value" lines rather than CSV records,
// matching DataRakeCSVWriter.writeSummary. Order is files, lines, bytes, hits.
func (w *CSVWriter) WriteSummary(s Summary) error {
	if !w.o.Summary {
		return nil
	}
	for _, line := range []string{
		fmt.Sprintf("files: %d", s.Files),
		fmt.Sprintf("lines: %d", s.Lines),
		fmt.Sprintf("bytes: %d", s.Bytes),
		fmt.Sprintf("hits: %d", s.Hits),
	} {
		if _, err := w.bw.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.bw.Flush()
}

func (w *CSVWriter) EndSummary() error { return w.bw.Flush() }
func (w *CSVWriter) EndOutput() error  { return w.bw.Flush() }
