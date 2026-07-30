package rake

import (
	"encoding/base64"
	"testing"
	"time"
)

const validJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG91IiwiaXNTb2NpYWwiOnRydWV9." +
	"4pcPyMD09olPSyXnrXCjTwXyr4BsezdI1AVTmud2fU4="

func TestJWTAuthMatchesValidToken(t *testing.T) {
	j, err := NewJWTAuth(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := j.Match(testCtx(1), "token = "+validJWT+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
}

func TestJWTAuthRejectsWhenHeaderIsNotJSON(t *testing.T) {
	j, _ := NewJWTAuth(time.Second)
	// Three well-formed base64 sections, but the header does not decode to JSON.
	notJSON := base64.StdEncoding.EncodeToString([]byte("this is not json at all!!"))
	tok := notJSON + "." + notJSON + "." + notJSON
	if got, _ := j.Match(testCtx(1), tok+"\n"); len(got) != 0 {
		t.Error("a non-JSON header must be filtered")
	}
}

func TestJWTAuthRejectsTwoPartStructure(t *testing.T) {
	j, _ := NewJWTAuth(time.Second)
	parts := validJWT[:len(validJWT)-1]
	two := parts[:44] + "." + parts[:44]
	if got, _ := j.Match(testCtx(1), two+"\n"); len(got) != 0 {
		t.Error("a two-part structure must not match")
	}
}

func TestJWTAuthSeverityAndType(t *testing.T) {
	j, _ := NewJWTAuth(time.Second)
	if j.PType() != "auth jwt" || j.Severity() != "MEDIUM" {
		t.Errorf("got type=%q severity=%q", j.PType(), j.Severity())
	}
}
