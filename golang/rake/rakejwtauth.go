package rake

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

// JWTAuth finds likely JWTs: header.payload.signature, where the header and
// payload are base64-encoded JSON. The third section is treated as opaque.
//
// A minimum of 24 base64 characters per section is a practical filter; a real
// header or payload is hard to encode in less.
//
// JWTs are not supposed to carry sensitive data, but one found in source may
// have been generated on a server and stored for later use. That storage is
// what this flags.
type JWTAuth struct {
	*Pattern
}

func NewJWTAuth(timeout time.Duration) (*JWTAuth, error) {
	pat := `\b(([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/_-]{24,}={0,2}))\b`

	zero := 0
	p, err := NewPattern(PatternOpts{
		Name: "RakeJWTAuth", PType: "auth jwt",
		PDesc:    "possible JavaScript web token",
		Severity: "MEDIUM",
		Pattern:  pat, CtxGroup: &zero, ValGroup: &zero,
		IgnoreCase: false, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	j := &JWTAuth{Pattern: p}
	j.SetSelf(j)
	return j, nil
}

// Filter requires both the header and the payload to base64-decode and parse
// as JSON. The signature is opaque and is not checked.
func (j *JWTAuth) Filter(m *match.RakeMatch) bool {
	// match_groups holds (whole, header, payload, signature).
	if len(m.MatchGroups) != 4 {
		return false
	}

	for _, section := range []string{m.MatchGroups[1], m.MatchGroups[2]} {
		// Reproduces the padding arithmetic at rakes.py:515 verbatim:
		//   st_padded = st + ("=" * (len(st) % 4))
		// For len%4 == 3 this adds three '=' where one is correct, so such a
		// section fails to decode and the match is filtered. Preserved
		// deliberately -- changing it would change which findings survive.
		padded := section + strings.Repeat("=", len(section)%4)

		raw, err := base64.StdEncoding.DecodeString(padded)
		if err != nil {
			return false
		}
		var any interface{}
		if err := json.Unmarshal(raw, &any); err != nil {
			return false
		}
	}

	return j.Pattern.Filter(m)
}
