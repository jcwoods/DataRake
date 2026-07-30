package rake

import (
	"fmt"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/match"
)

// DefaultTLDs mirrors RakeHostname.TLDs (rakes.py:344). These account for the
// large majority of hosts on the internet. Overridden by Global.CommonTLDs,
// whose shipped value omits "xyz".
var DefaultTLDs = []string{
	"au", "br", "cn", "com", "de", "edu", "gov", "in", "info", "ir",
	"mil", "net", "nl", "org", "ru", "tk", "top", "uk", "xyz",
}

// IsValidHostname applies the structural checks a regex cannot: overall
// length, label count, a recognized TLD, and per-label length.
func IsValidHostname(fqdn string, minparts int, tlds []string) bool {
	n := len(fqdn)
	if n < 2 || n > 255 {
		return false
	}

	labels := strings.Split(fqdn, ".")
	if len(labels) < minparts {
		return false
	}

	last := strings.ToLower(labels[len(labels)-1])
	found := false
	for _, t := range tlds {
		if last == t {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	for _, l := range labels {
		if len(l) > 63 {
			return false
		}
	}
	return true
}

// Hostname matches any host in a domain, including arbitrarily deep
// subdomains. With no domain, it requires three or more labels so that
// ordinary dotted symbols like "a.b" are not reported.
type Hostname struct {
	*Pattern
	tlds []string
}

func NewHostname(domain *string, tlds []string, timeout time.Duration) (*Hostname, error) {
	if tlds == nil {
		tlds = DefaultTLDs
	}

	var pat string
	if domain != nil {
		pat = `\b(([a-z1-9\-]{1,63}\.)+` + regexp2.Escape(*domain) + `)\b`
	} else {
		// An arbitrary call: a name must have 3 or more parts. This misses
		// things like "localhost.localdomain", which is acceptable because it
		// avoids reporting every "a.b" symbol. Change {2,6} to + to widen.
		pat = `\b([a-z1-9\-]{1,63}(\.[a-z1-9\-]{1,63}){2,6})\b`
	}

	desc := "a hostname (possible information disclosure)"
	if domain != nil {
		desc += fmt.Sprintf(" matching domain '%s'", *domain)
	}

	zero := 0
	p, err := NewPattern(PatternOpts{
		Name: "RakeHostname", PType: "hostname", PDesc: desc, Severity: "LOW",
		Pattern: pat, CtxGroup: &zero, ValGroup: &zero, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	h := &Hostname{Pattern: p, tlds: tlds}
	h.SetSelf(h) // route Pattern.Match's filtering through Hostname.Filter
	return h, nil
}

// Filter drops structurally invalid hostnames, then chains to the base
// denylist, reproducing Python's super().filter(m).
func (h *Hostname) Filter(m *match.RakeMatch) bool {
	v := m.Value(match.PlainOutput)
	if v == nil {
		return false
	}
	if !IsValidHostname(*v, 3, h.tlds) {
		return false
	}
	return h.Pattern.Filter(m)
}
