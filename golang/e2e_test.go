package datarake_test

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate golden files")

var binary string

func TestMain(m *testing.M) {
	flag.Parse()

	dir, err := os.MkdirTemp("", "datarake-e2e")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binary = filepath.Join(dir, "datarake")
	build := exec.Command("go", "build", "-o", binary, "./cmd/datarake")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

// runScan executes the binary and returns stdout with the scan root's absolute
// path normalized away.
func runScan(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(binary, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %v: %v\nstderr: %s", args, err, errb.String())
	}
	return out.String()
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run: go test ./ -update): %v", path, err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s\n got: %s\nwant: %s", path, got, want)
	}
}

func TestGoldenJSON(t *testing.T) {
	got := runScan(t, "-f", "json", "-u", "testdata/scan")
	checkGolden(t, "scan.json", got)
}

func TestGoldenCSV(t *testing.T) {
	got := runScan(t, "-f", "csv", "-u", "testdata/scan")
	checkGolden(t, "scan.csv", got)
}

func TestGoldenSecureJSON(t *testing.T) {
	got := runScan(t, "-f", "json", "-s", "testdata/scan")
	checkGolden(t, "scan-secure.json", got)
	if strings.Contains(got, "Sup3rSekrit!") {
		t.Error("secure mode leaked a secret")
	}
}

// The output must not depend on the worker count.
func TestOutputIsIdenticalAcrossJobCounts(t *testing.T) {
	base := runScan(t, "-f", "json", "-u", "-j", "1", "testdata/scan")
	for _, j := range []string{"2", "4", "8", "16"} {
		got := runScan(t, "-f", "json", "-u", "-j", j, "testdata/scan")
		if got != base {
			t.Errorf("-j %s output differs from -j 1\n got: %s\nwant: %s", j, got, base)
		}
	}
}

// Pins rune offsets: a byte-offset implementation reports different offsets.
//
// The fixture line is "# café: password=Sup3rSekrit1". The two-byte é sits
// before the match, so counting runes puts the context at 8 and the value at
// 17, while counting bytes would give 9 and 18. Verified against the Python,
// which indexes in characters and reports the same 8 and 17.
//
// The non-ASCII deliberately precedes the match rather than sitting inside the
// value: the password rake's value group is [\x21\x23-\x26\x28-\x7e], which is
// ASCII-only, so a non-ASCII value cannot match in either implementation.
func TestNonASCIILineUsesRuneOffsets(t *testing.T) {
	got := runScan(t, "-f", "json", "testdata/scan")
	if !strings.Contains(got, `"path": "utf8.properties"`) {
		t.Fatalf("expected a finding in utf8.properties:\n%s", got)
	}
	if !strings.Contains(got, `"context": {"value": "password=Sup3rSekrit1", "offset": 8, "length": 21}`) {
		t.Errorf("context offset must be the rune offset 8, not the byte offset 9:\n%s", got)
	}
	if !strings.Contains(got, `"value": {"value": "Sup3rSekrit1", "offset": 17, "length": 12}`) {
		t.Errorf("value offset must be the rune offset 17, not the byte offset 18:\n%s", got)
	}
}

func TestSshpassReportsNonEmptyValue(t *testing.T) {
	got := runScan(t, "-f", "json", "testdata/scan")
	if !strings.Contains(got, "superSekr3t") {
		t.Errorf("sshpass and auth url must report a non-empty value; master reports \"\":\n%s", got)
	}
}

func TestContextsAreNeverEmpty(t *testing.T) {
	got := runScan(t, "-f", "json", "testdata/scan")
	if strings.Contains(got, `"context": {"value": "", "offset": 0, "length": 0}`) {
		t.Errorf("no finding may carry an empty context; that is the master bug:\n%s", got)
	}
}

func TestQuietWithSummaryEmitsOnlySummary(t *testing.T) {
	got := runScan(t, "-f", "json", "-q", "-u", "testdata/scan")
	if strings.Contains(got, `"secrets"`) {
		t.Errorf("quiet must omit the secrets key: %s", got)
	}
	if !strings.Contains(got, `"summary"`) {
		t.Errorf("summary must be present: %s", got)
	}
}

func TestOutputToFile(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out.json")
	runScan(t, "-f", "json", "-o", dst, "testdata/scan")
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"secrets"`)) {
		t.Errorf("-o must write the document to the file: %s", b)
	}
}

func TestExcludedExtensionIsSkipped(t *testing.T) {
	// README.md has no findings, and the default blacklist excludes .css etc.
	got := runScan(t, "-f", "json", "testdata/scan")
	if strings.Contains(got, "README.md") {
		t.Errorf("README.md must produce no findings: %s", got)
	}
}
