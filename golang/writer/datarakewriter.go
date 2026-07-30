// Package writer renders findings in the supported output formats.
package writer

import (
	"io"

	"github.com/jcwoods/datarake/golang/match"
)

// Summary carries the run totals. Field order matches the JSON key order that
// json.dumps produces from the totals dict (files, lines, hits, bytes).
type Summary struct {
	Files int64
	Lines int64
	Hits  int64
	Bytes int64
}

// DataRakeWriter is the output contract. The lifecycle is:
//
//	InitOutput -> InitSecrets -> WriteSecret* -> EndSecrets ->
//	InitSummary -> WriteSummary -> EndSummary -> EndOutput
//
// Implementations are used only from the main goroutine.
type DataRakeWriter interface {
	InitOutput() error
	InitSecrets() error
	WriteSecret(m *match.RakeMatch) error
	EndSecrets() error
	InitSummary() error
	WriteSummary(s Summary) error
	EndSummary() error
	EndOutput() error
}

// Opts configures a writer.
type Opts struct {
	W       io.Writer
	Quiet   bool // suppress findings, summary only
	Summary bool // emit the summary block
	Output  *match.OutputConfig
}
