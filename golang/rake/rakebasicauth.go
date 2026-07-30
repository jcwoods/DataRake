package rake

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/jcwoods/datarake/golang/match"
)

// BasicAuth finds likely HTTP Basic auth tokens, eg:
//
//	Authorization: Basic dXNlcjpwYXNzd29yZAo=
//
// A minimum practical length of 16 keeps the base64 pattern from firing on
// short incidental strings. Candidates are decoded and required to contain a
// ':' as a minimal sanity check.
type BasicAuth struct {
	*Pattern
}

func NewBasicAuth(minlen int, timeout time.Duration) (*BasicAuth, error) {
	if minlen <= 0 {
		minlen = 16
	}
	pat := fmt.Sprintf(`(Basic ([A-Za-z0-9+/]{%d,}={0,8}))$`, minlen)

	zero, one := 0, 1
	p, err := NewPattern(PatternOpts{
		Name: "RakeBasicAuth", PType: "auth basic",
		PDesc:    "possible value used with an Authorization: header",
		Severity: "HIGH",
		Pattern:  pat, CtxGroup: &zero, ValGroup: &one,
		IgnoreCase: false, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	b := &BasicAuth{Pattern: p}
	b.SetSelf(b)
	return b, nil
}

// isPrintable mirrors Python's str.isprintable: every rune must be printable.
// Space counts as printable in both languages.
func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Filter decodes the candidate and requires printable text containing a colon
// at index 1 or later.
func (b *BasicAuth) Filter(m *match.RakeMatch) bool {
	// match_groups holds (whole, encoded); Python unpacks exactly two.
	if len(m.MatchGroups) != 2 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(m.MatchGroups[1])
	if err != nil {
		return false
	}
	val := strings.TrimSpace(string(raw))

	// find(":") < 1 rejects both "absent" (-1) and "at index 0".
	if !isPrintable(val) || strings.Index(val, ":") < 1 {
		return false
	}
	return b.Pattern.Filter(m)
}
