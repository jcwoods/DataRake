package writer

import (
	"bytes"
	"testing"

	"github.com/jcwoods/datarake/golang/match"
)

func TestJSONStringMatchesPythonJsonDumps(t *testing.T) {
	cases := map[string]string{
		"plain":      `"plain"`,
		`with"quote`: `"with\"quote"`,
		`back\slash`: `"back\\slash"`,
		"tab\there":  `"tab\there"`,
		"nl\nhere":   `"nl\nhere"`,
		"cr\rhere":   `"cr\rhere"`,
		// Python leaves these literal; encoding/json would escape them.
		"a<b>c&d": `"a<b>c&d"`,
		// ensure_ascii=True escapes non-ASCII, including DEL.
		"héllo": `"h\u00e9llo"`,
		"日本":    `"\u65e5\u672c"`,
		"\x7f":  `"\u007f"`,
		"\x01":  `"\u0001"`,
		// Astral plane becomes a surrogate pair.
		"\U0001F600": `"\ud83d\ude00"`,
	}
	for in, want := range cases {
		if got := JSONString(in); got != want {
			t.Errorf("JSONString(%q):\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestJSONWriterFullDocument(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewJSONWriter(Opts{W: &buf, Summary: true, Output: oc})

	if err := w.InitOutput(); err != nil {
		t.Fatal(err)
	}
	w.InitSecrets()
	if err := w.WriteSecret(sampleMatch()); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteSecret(sampleMatch()); err != nil {
		t.Fatal(err)
	}
	w.EndSecrets()
	w.InitSummary()
	w.WriteSummary(Summary{Files: 1, Lines: 2, Hits: 2, Bytes: 46})
	w.EndSummary()
	if err := w.EndOutput(); err != nil {
		t.Fatal(err)
	}

	secret := `{"path": "src/a.properties", "line": 2, "type": "password", ` +
		`"description": "possible plaintext password", "severity": "HIGH", ` +
		`"context": {"value": "password=Sup3rSekrit!", "offset": 0, "length": 20}, ` +
		`"value": {"value": "Sup3rSekrit!", "offset": 9, "length": 12}}`
	// Note the summary key order: files, lines, hits, bytes -- the insertion
	// order of the totals dict, which differs from the CSV summary's order.
	want := `{"secrets": [` + secret + `,` + secret + `],"summary": ` +
		`{"files": 1, "lines": 2, "hits": 2, "bytes": 46}}` + "\n"

	if buf.String() != want {
		t.Errorf("document mismatch:\n got %s\nwant %s", buf.String(), want)
	}
}

func TestJSONWriterNullLineForFileMeta(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewJSONWriter(Opts{W: &buf, Output: oc})
	m := match.New(fakeRake{"ssh identity file", "d", "HIGH"}, "id_rsa", nil)

	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(m)
	w.EndSecrets()
	w.EndOutput()

	want := `{"secrets": [{"path": "id_rsa", "line": null, "type": "ssh identity file", ` +
		`"description": "d", "severity": "HIGH", ` +
		`"context": {"value": null, "offset": null, "length": null}, ` +
		`"value": {"value": null, "offset": null, "length": null}}]}` + "\n"
	if buf.String() != want {
		t.Errorf("mismatch:\n got %s\nwant %s", buf.String(), want)
	}
}

func TestJSONWriterQuietWithSummaryOmitsSecretsKey(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewJSONWriter(Opts{W: &buf, Quiet: true, Summary: true, Output: oc})

	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	w.InitSummary()
	w.WriteSummary(Summary{Files: 1})
	w.EndSummary()
	w.EndOutput()

	// No leading comma: _keys_written stays 0 because InitSecrets returned early.
	want := `{"summary": {"files": 1, "lines": 0, "hits": 0, "bytes": 0}}` + "\n"
	if buf.String() != want {
		t.Errorf("mismatch:\n got %s\nwant %s", buf.String(), want)
	}
}

func TestJSONWriterDisableContextOmitsContextObject(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, true, false)
	w := NewJSONWriter(Opts{W: &buf, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	w.EndOutput()

	got := buf.String()
	if bytes.Contains([]byte(got), []byte(`"context"`)) {
		t.Errorf("disable-context must omit the context object: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte(`"value"`)) {
		t.Errorf("the value object must remain: %s", got)
	}
}

func TestJSONWriterSecureModeHashesContextAndNullsValue(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(true, false, false)
	w := NewJSONWriter(Opts{W: &buf, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	w.EndOutput()

	got := buf.String()
	if bytes.Contains([]byte(got), []byte("Sup3rSekrit!")) {
		t.Errorf("secure mode leaked the secret: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte(`"value": {"value": null`)) {
		t.Errorf("secure mode must null the value: %s", got)
	}
	if bytes.Contains([]byte(got), []byte("password=Sup3rSekrit!")) {
		t.Errorf("secure mode must hash the context: %s", got)
	}
}
