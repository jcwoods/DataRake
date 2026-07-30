package writer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jcwoods/datarake/golang/match"
)

type fakeRake struct{ t, d, s string }

func (f fakeRake) PType() string    { return f.t }
func (f fakeRake) PDesc() string    { return f.d }
func (f fakeRake) Severity() string { return f.s }

func ip(i int) *int { return &i }

func sampleMatch() *match.RakeMatch {
	m := match.New(fakeRake{"password", "possible plaintext password", "HIGH"}, "src/a.properties", ip(2))
	m.SetContext("password=Sup3rSekrit!", 0, 20)
	m.SetValue("Sup3rSekrit!", 9, 12)
	return m
}

func TestCSVFieldQuotesOnlyWhatPythonQuotes(t *testing.T) {
	cases := map[string]string{
		"plain":             "plain",
		"  leading spaces":  "  leading spaces",  // Python does NOT quote
		"trailing spaces  ": "trailing spaces  ", // nor these
		"has,comma":         `"has,comma"`,
		`has"quote`:         `"has""quote"`,
		"has\nnewline":      "\"has\nnewline\"",
		"has\rcr":           "\"has\rcr\"",
		"":                  "",
	}
	for in, want := range cases {
		if got := CSVField(in); got != want {
			t.Errorf("CSVField(%q): got %q want %q", in, got, want)
		}
	}
}

func TestCSVWriterEmitsHeaderAndRowWithCRLF(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Output: oc})

	for _, step := range []func() error{
		w.InitOutput, w.InitSecrets,
		func() error { return w.WriteSecret(sampleMatch()) },
		w.EndSecrets, w.InitSummary,
		func() error { return w.WriteSummary(Summary{}) },
		w.EndSummary, w.EndOutput,
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}

	got := buf.String()
	lines := strings.Split(strings.TrimSuffix(got, "\r\n"), "\r\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 row, got %d lines from %q", len(lines), got)
	}
	wantHeader := "file,line,label,severity,description," +
		"value_offset,value_length,value,context_offset,context_length,context"
	if lines[0] != wantHeader {
		t.Errorf("header:\n got %q\nwant %q", lines[0], wantHeader)
	}
	wantRow := "src/a.properties,2,password,HIGH,possible plaintext password," +
		"9,12,Sup3rSekrit!,0,20,password=Sup3rSekrit!"
	if lines[1] != wantRow {
		t.Errorf("row:\n got %q\nwant %q", lines[1], wantRow)
	}
}

func TestCSVWriterQuietSuppressesHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Quiet: true, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	if buf.Len() != 0 {
		t.Errorf("quiet mode must emit nothing, got %q", buf.String())
	}
}

func TestCSVWriterSummaryFormat(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Quiet: true, Summary: true, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.EndSecrets()
	w.InitSummary()
	if err := w.WriteSummary(Summary{Files: 3, Lines: 40, Hits: 5, Bytes: 900}); err != nil {
		t.Fatal(err)
	}
	w.EndSummary()
	w.EndOutput()

	want := "files: 3\nlines: 40\nbytes: 900\nhits: 5\n"
	if buf.String() != want {
		t.Errorf("summary:\n got %q\nwant %q", buf.String(), want)
	}
}

func TestCSVWriterSummaryDisabledEmitsNothing(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Quiet: true, Summary: false, Output: oc})
	w.InitSummary()
	w.WriteSummary(Summary{Files: 1})
	w.EndSummary()
	if buf.Len() != 0 {
		t.Errorf("summary must be suppressed, got %q", buf.String())
	}
}

func TestCSVWriterSecureModeDropsValueColumn(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(true, false, false)
	w := NewCSVWriter(Opts{W: &buf, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\r\n"), "\r\n")
	if strings.Contains(lines[0], ",value,") {
		t.Errorf("secure mode must drop the value column: %q", lines[0])
	}
	if strings.Contains(lines[1], "Sup3rSekrit!") {
		t.Errorf("secure mode leaked the secret: %q", lines[1])
	}
	if !strings.Contains(lines[0], "context") {
		t.Errorf("secure mode must keep the context column: %q", lines[0])
	}
}
