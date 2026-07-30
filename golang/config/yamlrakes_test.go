package config_test

import (
	"testing"
	"time"

	datarake "github.com/jcwoods/datarake/golang"
	"github.com/jcwoods/datarake/golang/config"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

func realConfig(t *testing.T) *config.Config {
	t.Helper()
	c, err := config.Load(datarake.DefaultConfig, time.Second)
	if err != nil {
		t.Fatalf("load embedded config: %v", err)
	}
	return c
}

// ctx builds a scan context. line defaults to 1 when omitted.
func ctx(name, ext string, line ...int) *walker.Context {
	n := 1
	if len(line) > 0 {
		n = line[0]
	}
	has := ext != ""
	return &walker.Context{
		BasePath: "/src", Path: "/src", Filename: name,
		FullPath: "/src/" + name, FileType: ext, HasFileType: has,
		LineNo: &n,
	}
}

// scanLine runs every content rake in the real config over one line.
func scanLine(t *testing.T, c *config.Config, name, ext, text string) []*match.RakeMatch {
	t.Helper()
	got, err := c.RakeSet.MatchContent(ctx(name, ext, 1), text)
	if err != nil {
		t.Fatalf("MatchContent: %v", err)
	}
	return got
}

func findByLabel(ms []*match.RakeMatch, label string) *match.RakeMatch {
	for _, m := range ms {
		if m.Label() == label {
			return m
		}
	}
	return nil
}

// The headline regression: master reports an empty context for every content
// finding. The README documents this exact example.
func TestPasswordRakeReportsFullContextAndValue(t *testing.T) {
	c := realConfig(t)
	oc := match.NewOutputConfig(false, false, false)

	got := scanLine(t, c, "project.properties", "properties", "password=Sup3rSekrit!\n")
	m := findByLabel(got, "password")
	if m == nil {
		t.Fatalf("no password finding in %d matches", len(got))
	}

	if v := m.Context(oc); v == nil || *v != "password=Sup3rSekrit!" {
		t.Errorf("context: got %v want %q", v, "password=Sup3rSekrit!")
	}
	if v := m.ContextOffset(); v == nil || *v != 0 {
		t.Errorf("context offset: got %v want 0", v)
	}
	if v := m.ContextLength(); v == nil || *v != 21 {
		t.Errorf("context length: got %v want 21", v)
	}
	if v := m.Value(oc); v == nil || *v != "Sup3rSekrit!" {
		t.Errorf("value: got %v want %q", v, "Sup3rSekrit!")
	}
	if v := m.ValueOffset(); v == nil || *v != 9 {
		t.Errorf("value offset: got %v want 9", v)
	}
	if v := m.ValueLength(); v == nil || *v != 12 {
		t.Errorf("value length: got %v want 12", v)
	}
}

func TestTokenRakeReportsNonEmptyValueAndBalancedContext(t *testing.T) {
	c := realConfig(t)
	oc := match.NewOutputConfig(false, false, false)

	got := scanLine(t, c, "app.conf", "conf", "authtoken=\"s3kr3tvalue\"\n")
	m := findByLabel(got, "token")
	if m == nil {
		t.Fatalf("no token finding in %d matches", len(got))
	}
	if v := m.Value(oc); v == nil || *v != "s3kr3tvalue" {
		t.Errorf("value: got %v want %q (master reports \"\")", v, "s3kr3tvalue")
	}
	// The (\5)->(\6) fix closes the quote.
	if v := m.Context(oc); v == nil || *v != `authtoken="s3kr3tvalue"` {
		t.Errorf("context: got %v want %q", v, `authtoken="s3kr3tvalue"`)
	}
}

func TestSshpassRakeReportsPassword(t *testing.T) {
	c := realConfig(t)
	oc := match.NewOutputConfig(false, false, false)

	got := scanLine(t, c, "test1.sh", "sh", "sshpass -psuperSekr3t jeff@somehost.com\n")
	m := findByLabel(got, "sshpass")
	if m == nil {
		t.Fatalf("no sshpass finding in %d matches", len(got))
	}
	if v := m.Value(oc); v == nil || *v != "superSekr3t" {
		t.Errorf("value: got %v want %q (master reports \"\")", v, "superSekr3t")
	}
	if v := m.Context(oc); v == nil || *v != "sshpass -psuperSekr3t" {
		t.Errorf("context: got %v want %q", v, "sshpass -psuperSekr3t")
	}
}

func TestAuthURLRakeAlreadyCorrect(t *testing.T) {
	c := realConfig(t)
	oc := match.NewOutputConfig(false, false, false)

	got := scanLine(t, c, "t.sh", "sh", "wget https://jeff:superSekr3t@someremotehost.com/x\n")
	m := findByLabel(got, "auth url")
	if m == nil {
		t.Fatalf("no auth url finding in %d matches", len(got))
	}
	// valgroup 3 -> regex group 4 -> the password.
	if v := m.Value(oc); v == nil || *v != "superSekr3t" {
		t.Errorf("value: got %v want %q", v, "superSekr3t")
	}
}

func TestPrivateKeyRake(t *testing.T) {
	c := realConfig(t)
	oc := match.NewOutputConfig(false, false, false)

	got := scanLine(t, c, "k.pem", "pem", "-----BEGIN RSA PRIVATE KEY-----\n")
	m := findByLabel(got, "private key")
	if m == nil {
		t.Fatalf("no private key finding in %d matches", len(got))
	}
	if v := m.Context(oc); v == nil || *v != "-----BEGIN RSA PRIVATE KEY-----" {
		t.Errorf("context: got %v", v)
	}
}

// The private key rake carries a `type: literal, value: ENCRYPTED` filter and
// the config comments it as "ignore ENCRYPTED private key". That filter is
// inert, and this test pins the real behavior rather than the intended one.
//
// The rake defines no valgroup, so a match's value is never set. Python's
// RakeLiteralFilter returns False whenever the value is None (common.py:760),
// so the filter never fires and the finding survives. Verified against the
// Python tool directly: scanning a file containing only
// "-----BEGIN ENCRYPTED PRIVATE KEY-----" emits a "private key" finding.
//
// Making the filter work would mean adding a valgroup to datarake.yaml, which
// changes which findings the scanner reports. That is a fix to the config, not
// part of porting it.
func TestPrivateKeyRakeEncryptedIsNotFilteredInertENCRYPTEDFilter(t *testing.T) {
	c := realConfig(t)
	got := scanLine(t, c, "k.pem", "pem", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
	m := findByLabel(got, "private key")
	if m == nil {
		t.Fatal("the ENCRYPTED literal filter is inert (no valgroup), so the finding must survive, matching Python")
	}
	if v := m.Value(match.PlainOutput); v != nil {
		t.Errorf("the rake sets no valgroup, so the value must stay unset; got %q", *v)
	}
}

func TestPasswordRakeFiltersTemplateVariables(t *testing.T) {
	c := realConfig(t)
	for _, line := range []string{
		"password=$PASSWORD\n",
		"password=${PASSWORD}\n",
		"password={{ password }}\n",
		"password=XXXXXX\n",
		"password=passwd\n",
		"password=abc\n", // shorter than six characters
	} {
		got := scanLine(t, c, "a.properties", "properties", line)
		if m := findByLabel(got, "password"); m != nil {
			t.Errorf("line %q must be filtered but reported a finding", line)
		}
	}
}

func TestSensitiveEnvVarRakesPerLanguage(t *testing.T) {
	c := realConfig(t)
	oc := match.NewOutputConfig(false, false, false)

	cases := []struct{ ext, line, want string }{
		{"py", `pw = os.getenv("DB_PASSWORD", "hunter2")` + "\n", "hunter2"},
		{"js", `const p = process.env.PASSWORD || 'hunter2'` + "\n", "hunter2"},
		{"cs", `var p = Environment.GetEnvironmentVariable("PASSWORD") ?? "hunter2";` + "\n", "hunter2"},
		{"java", `@Value("${password:hunter2}")` + "\n", "hunter2"},
	}
	for _, tc := range cases {
		got := scanLine(t, c, "f."+tc.ext, tc.ext, tc.line)
		m := findByLabel(got, "sensitive environment variable with default")
		if m == nil {
			t.Errorf("ext %q: no finding for %q", tc.ext, tc.line)
			continue
		}
		if v := m.Value(oc); v == nil || *v != tc.want {
			t.Errorf("ext %q: value got %v want %q", tc.ext, v, tc.want)
		}
	}
}

// The FileMeta rakes from the shipped config.
func TestYAMLFileMetaRakes(t *testing.T) {
	c := realConfig(t)
	cases := []struct {
		name, ext, wantLabel string
	}{
		{"id_rsa", "", "ssh identity file"},
		{"id_ecdsa", "", "ssh identity file"},
		{".netrc", "netrc", "netrc file"},
		{"server.pem", "pem", "pki file"},
		{"keystore.jks", "jks", "java keystore file"},
		{".htpasswd", "htpasswd", "htpasswd file"},
	}
	for _, tc := range cases {
		got, err := c.RakeSet.MatchContext(ctx(tc.name, tc.ext, 0))
		if err != nil {
			t.Fatal(err)
		}
		if findByLabel(got, tc.wantLabel) == nil {
			t.Errorf("%q: expected a %q finding, got %d matches", tc.name, tc.wantLabel, len(got))
		}
	}
}

func TestYAMLFileMetaNegatives(t *testing.T) {
	c := realConfig(t)
	got, err := c.RakeSet.MatchContext(ctx("README.md", "md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("README.md must produce no filemeta findings, got %d", len(got))
	}
}
