package rake

import (
	"strings"
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

func mustHostname(t *testing.T, domain *string) *Hostname {
	t.Helper()
	h, err := NewHostname(domain, DefaultTLDs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHostnameMatchesThreePartFQDN(t *testing.T) {
	h := mustHostname(t, nil)
	got, err := h.Match(testCtx(1), "connect to srv.example.com now\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := got[0].Value(oc); v == nil || *v != "srv.example.com" {
		t.Errorf("value: got %v", v)
	}
}

func TestHostnameRejectsUnknownTLD(t *testing.T) {
	h := mustHostname(t, nil)
	got, _ := h.Match(testCtx(1), "srv.example.invalidtld\n")
	if len(got) != 0 {
		t.Errorf("an unknown TLD must be filtered, got %d", len(got))
	}
}

func TestHostnameTwoPartNotMatchedByDefault(t *testing.T) {
	h := mustHostname(t, nil)
	got, _ := h.Match(testCtx(1), "just example.com here\n")
	if len(got) != 0 {
		t.Errorf("a two-part name must not match the default pattern, got %d", len(got))
	}
}

func TestHostnameDomainRestriction(t *testing.T) {
	d := "example.com"
	h := mustHostname(t, &d)
	if got, _ := h.Match(testCtx(1), "a.example.com\n"); len(got) != 1 {
		t.Errorf("expected a match in the restricted domain, got %d", len(got))
	}
	if got, _ := h.Match(testCtx(1), "a.other.com\n"); len(got) != 0 {
		t.Errorf("expected no match outside the restricted domain, got %d", len(got))
	}
	// The domain must be regex-escaped, so the dot is literal.
	if got, _ := h.Match(testCtx(1), "a.examplexcom\n"); len(got) != 0 {
		t.Errorf("the domain must be escaped so '.' is literal, got %d", len(got))
	}
}

func TestHostnameDescriptionMentionsDomain(t *testing.T) {
	d := "example.com"
	h := mustHostname(t, &d)
	want := "a hostname (possible information disclosure) matching domain 'example.com'"
	if h.PDesc() != want {
		t.Errorf("description:\n got %q\nwant %q", h.PDesc(), want)
	}
	plain := mustHostname(t, nil)
	if plain.PDesc() != "a hostname (possible information disclosure)" {
		t.Errorf("description: got %q", plain.PDesc())
	}
}

func TestIsValidHostname(t *testing.T) {
	long := strings.Repeat("a", 64)
	cases := []struct {
		fqdn     string
		minparts int
		want     bool
	}{
		{"srv.example.com", 3, true},
		{"a", 3, false},                   // too short
		{"example.com", 3, false},         // too few parts
		{"example.com", 2, true},          // minparts override
		{"srv.example.zzz", 3, false},     // bad TLD
		{"srv.example.COM", 3, true},      // TLD compared case-insensitively
		{long + ".example.com", 3, false}, // label > 63
	}
	for _, tc := range cases {
		if got := IsValidHostname(tc.fqdn, tc.minparts, DefaultTLDs); got != tc.want {
			t.Errorf("IsValidHostname(%q, %d): got %v want %v", tc.fqdn, tc.minparts, got, tc.want)
		}
	}
}

func TestIsValidHostnameHonorsSuppliedTLDList(t *testing.T) {
	// Global.CommonTLDs in the shipped config omits "xyz", which DefaultTLDs
	// includes. A caller-supplied list must win.
	if IsValidHostname("a.b.xyz", 3, DefaultTLDs) != true {
		t.Error("DefaultTLDs includes xyz")
	}
	short := []string{"com", "net"}
	if IsValidHostname("a.b.xyz", 3, short) != false {
		t.Error("a supplied TLD list must be honored")
	}
}
