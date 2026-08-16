package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	datarake "github.com/jcwoods/datarake/golang"
)

func TestParseDefaults(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.paths) != 1 || o.paths[0] != "." {
		t.Errorf("PATH must default to [.], got %#v", o.paths)
	}
	if o.format != "json" {
		t.Errorf("format must default to json, got %q", o.format)
	}
	if o.jobs <= 0 {
		t.Errorf("jobs must default to the CPU count, got %d", o.jobs)
	}
	if o.secure || o.quiet || o.summary || o.verbose || o.disableContext || o.disableValue {
		t.Errorf("boolean flags must default to false: %#v", o)
	}
}

func TestParseMultiplePaths(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "src", "lib"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.paths) != 2 || o.paths[0] != "src" || o.paths[1] != "lib" {
		t.Errorf("paths: %#v", o.paths)
	}
}

// argparse accepts flags after positionals; pflag must too.
func TestParseInterspersedFlags(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "src", "-v", "-f", "csv"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.verbose {
		t.Error("a flag after a positional must be parsed")
	}
	if o.format != "csv" {
		t.Errorf("format: got %q want csv", o.format)
	}
	if len(o.paths) != 1 || o.paths[0] != "src" {
		t.Errorf("paths: %#v", o.paths)
	}
}

func TestParseMultiCharShortFlags(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "-dx", "-dv"})
	if err != nil {
		t.Fatalf("-dx/-dv must be accepted for argparse compatibility: %v", err)
	}
	if !o.disableContext {
		t.Error("-dx must set disable-context")
	}
	if !o.disableValue {
		t.Error("-dv must set disable-value")
	}

	o2, err := parseCmdLine([]string{"datarake", "--disable-context", "--disable-value"})
	if err != nil {
		t.Fatal(err)
	}
	if !o2.disableContext || !o2.disableValue {
		t.Error("long forms must work too")
	}
}

func TestParseFormatChoices(t *testing.T) {
	for _, f := range []string{"csv", "json"} {
		if _, err := parseCmdLine([]string{"datarake", "-f", f}); err != nil {
			t.Errorf("format %q must be accepted: %v", f, err)
		}
	}
	// SARIF is dropped in the Go port.
	if _, err := parseCmdLine([]string{"datarake", "-f", "sarif"}); err == nil {
		t.Error("sarif must be rejected")
	}
	if _, err := parseCmdLine([]string{"datarake", "-f", "xml"}); err == nil {
		t.Error("an unknown format must be rejected")
	}
}

func TestParseEqualsForm(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "--format=csv", "--jobs=3"})
	if err != nil {
		t.Fatal(err)
	}
	if o.format != "csv" || o.jobs != 3 {
		t.Errorf("got format=%q jobs=%d", o.format, o.jobs)
	}
}

// A non-positive -j falls back to the CPU count, as in Python.
func TestParseNonPositiveJobsFallsBack(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "-j", "0"})
	if err != nil {
		t.Fatal(err)
	}
	if o.jobs <= 0 {
		t.Errorf("jobs must fall back to a positive value, got %d", o.jobs)
	}
}

func TestParseMatchTimeout(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "--match-timeout", "250ms"})
	if err != nil {
		t.Fatal(err)
	}
	if o.matchTimeout.String() != "250ms" {
		t.Errorf("match timeout: got %v", o.matchTimeout)
	}
	def, _ := parseCmdLine([]string{"datarake"})
	if def.matchTimeout.String() != "1s" {
		t.Errorf("match timeout must default to 1s, got %v", def.matchTimeout)
	}
}

func TestParseInitConfig(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "--init-config"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.initConfig {
		t.Error("--init-config must set initConfig")
	}
}

// chdirTemp switches to a fresh temp directory for the duration of the test.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestRunInitConfigWritesEmbeddedConfig(t *testing.T) {
	chdirTemp(t)

	o, err := parseCmdLine([]string{"datarake", "--init-config"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := run(o)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code: got %d want 0", code)
	}

	got, err := os.ReadFile("datarake.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, datarake.DefaultConfig) {
		t.Error("written config must match the embedded default")
	}
}

func TestRunInitConfigRefusesToOverwrite(t *testing.T) {
	chdirTemp(t)

	const existing = "custom: true\n"
	if err := os.WriteFile("datarake.yaml", []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	o, err := parseCmdLine([]string{"datarake", "--init-config"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := run(o)
	if err == nil {
		t.Error("run must refuse to overwrite an existing datarake.yaml")
	}
	if code == 0 {
		t.Error("exit code must be non-zero on refusal")
	}

	got, err := os.ReadFile("datarake.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != existing {
		t.Error("existing file must not be modified")
	}
}

func TestUsageMentionsEveryFlag(t *testing.T) {
	usage := usageString()
	for _, f := range []string{
		"--format", "--output", "--secure", "--disable-context", "--disable-value",
		"--summary", "--quiet", "--verbose", "--jobs", "--config", "--init-config", "--match-timeout",
	} {
		if !strings.Contains(usage, f) {
			t.Errorf("usage must document %s:\n%s", f, usage)
		}
	}
	if strings.Contains(usage, "sarif") {
		t.Error("usage must not advertise sarif")
	}
}
