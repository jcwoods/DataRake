package rake

import (
	"fmt"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/match"
)

// Email detects email addresses, optionally restricted to one domain.
type Email struct {
	*Pattern
	tlds []string
}

func NewEmail(domain *string, tlds []string, timeout time.Duration) (*Email, error) {
	if tlds == nil {
		tlds = DefaultTLDs
	}

	var pat string
	if domain != nil {
		pat = `([a-zA-Z1-9_.\-]{1,63}@` + regexp2.Escape(*domain) + `)`
	} else {
		pat = `([a-zA-Z0-9_.\-]{1,63}@[A-Za-z0-9_\-]{1,63}(\.[A-Za-z0-9_\-]{1,63}){1,6})`
	}

	desc := "an email address (possible information disclosure)"
	if domain != nil {
		desc += fmt.Sprintf(" matching domain '%s'", *domain)
	}

	zero := 0
	p, err := NewPattern(PatternOpts{
		Name: "RakeEmail", PType: "email", PDesc: desc, Severity: "LOW",
		Pattern: pat, CtxGroup: &zero, ValGroup: &zero, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	e := &Email{Pattern: p, tlds: tlds}
	e.SetSelf(e)
	return e, nil
}

// Filter requires exactly one '@' and a valid host part. Unlike Hostname, the
// host needs only two labels, so "user@example.com" is accepted.
func (e *Email) Filter(m *match.RakeMatch) bool {
	v := m.Value(match.PlainOutput)
	if v == nil {
		return false
	}

	// Python does user, host = email.split("@"), which raises ValueError -- and
	// so filters the match -- unless there is exactly one '@'.
	parts := strings.Split(*v, "@")
	if len(parts) != 2 {
		return false
	}
	if !IsValidHostname(parts[1], 2, e.tlds) {
		return false
	}
	return e.Pattern.Filter(m)
}
