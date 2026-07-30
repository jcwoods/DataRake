package rake

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

func TestBasicAuthMatchesValidToken(t *testing.T) {
	b, err := NewBasicAuth(16, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tok := base64.StdEncoding.EncodeToString([]byte("user:password"))
	got, err := b.Match(testCtx(1), "Authorization: Basic "+tok+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
}

// The decoded payload must contain a colon at index >= 1.
func TestBasicAuthRejectsDecodeWithoutColon(t *testing.T) {
	b, _ := NewBasicAuth(16, time.Second)
	tok := base64.StdEncoding.EncodeToString([]byte("nocolonhereatall"))
	if got, _ := b.Match(testCtx(1), "Authorization: Basic "+tok+"\n"); len(got) != 0 {
		t.Error("a payload with no colon must be filtered")
	}
	lead := base64.StdEncoding.EncodeToString([]byte(":leadingcolononly"))
	if got, _ := b.Match(testCtx(1), "Authorization: Basic "+lead+"\n"); len(got) != 0 {
		t.Error("a colon at index 0 must be filtered (find(\":\") < 1)")
	}
}

func TestBasicAuthRejectsNonPrintableDecode(t *testing.T) {
	b, _ := NewBasicAuth(16, time.Second)
	tok := base64.StdEncoding.EncodeToString([]byte("user:\x01\x02badbytes"))
	if got, _ := b.Match(testCtx(1), "Authorization: Basic "+tok+"\n"); len(got) != 0 {
		t.Error("a non-printable payload must be filtered")
	}
}

// The pattern is anchored with $, so it only matches at end of line.
func TestBasicAuthOnlyMatchesAtEndOfLine(t *testing.T) {
	b, _ := NewBasicAuth(16, time.Second)
	tok := base64.StdEncoding.EncodeToString([]byte("user:password"))
	if got, _ := b.Match(testCtx(1), "Basic "+tok+" trailing text\n"); len(got) != 0 {
		t.Error("$ must prevent a mid-line match")
	}
	// $ still matches immediately before a trailing newline.
	if got, _ := b.Match(testCtx(1), "Basic "+tok+"\n"); len(got) != 1 {
		t.Error("$ must match before the trailing newline")
	}
}

func TestBasicAuthGroupsCtxAndValue(t *testing.T) {
	b, _ := NewBasicAuth(16, time.Second)
	tok := base64.StdEncoding.EncodeToString([]byte("user:password"))
	got, _ := b.Match(testCtx(1), "Basic "+tok+"\n")
	if len(got) != 1 {
		t.Fatal("expected 1 match")
	}
	oc := match.PlainOutput
	if v := got[0].Context(oc); v == nil || *v != "Basic "+tok {
		t.Errorf("context must be the whole token: got %v", v)
	}
	if v := got[0].Value(oc); v == nil || *v != tok {
		t.Errorf("value must be the base64 payload: got %v", v)
	}
}
