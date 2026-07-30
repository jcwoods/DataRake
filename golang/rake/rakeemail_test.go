package rake

import (
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

func mustEmail(t *testing.T, domain *string) *Email {
	t.Helper()
	e, err := NewEmail(domain, DefaultTLDs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEmailMatchesBasicAddress(t *testing.T) {
	e := mustEmail(t, nil)
	got, err := e.Match(testCtx(1), "mail jeff@example.com today\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := got[0].Value(oc); v == nil || *v != "jeff@example.com" {
		t.Errorf("value: got %v", v)
	}
}

// Email uses minparts=2, so a two-part domain is valid here.
func TestEmailAcceptsTwoPartDomain(t *testing.T) {
	e := mustEmail(t, nil)
	if got, _ := e.Match(testCtx(1), "jeff@example.com\n"); len(got) != 1 {
		t.Error("a two-part domain must be accepted for email")
	}
}

func TestEmailRejectsBadTLD(t *testing.T) {
	e := mustEmail(t, nil)
	if got, _ := e.Match(testCtx(1), "jeff@example.zzz\n"); len(got) != 0 {
		t.Error("a bad TLD must be filtered")
	}
}

func TestEmailDomainRestriction(t *testing.T) {
	d := "example.com"
	e := mustEmail(t, &d)
	if got, _ := e.Match(testCtx(1), "jeff@example.com\n"); len(got) != 1 {
		t.Error("expected a match in the restricted domain")
	}
	if got, _ := e.Match(testCtx(1), "jeff@other.com\n"); len(got) != 0 {
		t.Error("expected no match outside the restricted domain")
	}
}
