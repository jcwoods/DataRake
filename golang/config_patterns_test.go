package datarake

import (
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v3"
)

// walkPatterns yields every regex string in the config: rake patterns,
// per-context patterns, and every filter key/value pattern.
func walkPatterns(t *testing.T) map[string]string {
	t.Helper()
	var cfg struct {
		FilterRegistry []map[string][]map[string]any `yaml:"FilterRegistry"`
		Rakes          []map[string]any              `yaml:"Rakes"`
	}
	if err := yaml.Unmarshal(DefaultConfig, &cfg); err != nil {
		t.Fatalf("unmarshal embedded config: %v", err)
	}

	out := map[string]string{}
	addFilters := func(label string, filters any) {
		list, ok := filters.([]any)
		if !ok {
			return
		}
		for i, f := range list {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			for _, k := range []string{"key", "value"} {
				if s, ok := fm[k].(string); ok && s != "" {
					out[label+".filter"+string(rune('0'+i))+"."+k] = s
				}
			}
		}
	}

	for _, entry := range cfg.FilterRegistry {
		for kind, items := range entry {
			for i, item := range items {
				for _, k := range []string{"key", "value"} {
					if s, ok := item[k].(string); ok && s != "" {
						out[kind+string(rune('0'+i))+"."+k] = s
					}
				}
				addFilters(kind, item["filters"])
			}
		}
	}

	for _, r := range cfg.Rakes {
		name, _ := r["name"].(string)
		if p, ok := r["pattern"].(string); ok {
			out[name+".pattern"] = p
		}
		for _, k := range []string{"path", "file", "extension"} {
			if s, ok := r[k].(string); ok && s != "" {
				out[name+"."+k] = s
			}
		}
		addFilters(name, r["filters"])
		if ctxs, ok := r["contexts"].([]any); ok {
			for i, c := range ctxs {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if p, ok := cm["pattern"].(string); ok {
					out[name+".context"+string(rune('0'+i))+".pattern"] = p
				}
				addFilters(name+".context"+string(rune('0'+i)), cm["filters"])
			}
		}
	}
	return out
}

func TestEveryConfigPatternCompiles(t *testing.T) {
	for label, pat := range walkPatterns(t) {
		re, err := regexp2.Compile(pat, regexp2.IgnoreCase)
		if err != nil {
			t.Errorf("%s: does not compile under regexp2: %v\n  pattern: %s", label, err, pat)
			continue
		}
		re.MatchTimeout = time.Second
	}
}

func TestNoBraceShorthandRemains(t *testing.T) {
	// regexp2 (.NET semantics) treats {,N} as a literal, not {0,N}.
	for label, pat := range walkPatterns(t) {
		re := regexp2.MustCompile(`\{,\d`, regexp2.None)
		if ok, _ := re.MatchString(pat); ok {
			t.Errorf("%s: contains {,N} shorthand, which regexp2 reads as a literal: %s", label, pat)
		}
	}
}

// TestCorrectedGroupNumbers pins the group corrections. Config group k maps to
// regex group k+1 (rakes.py:151), so we assert on k+1 here.
func TestCorrectedGroupNumbers(t *testing.T) {
	cases := []struct {
		name                       string
		pattern                    string
		input                      string
		ctxGroup, keyGroup, valGrp int // config-level numbers
		wantCtx, wantKey, wantVal  string
	}{
		{
			name:     "token/null",
			pattern:  `((["']?)([a-z0-9_]{0,32}tok(en)?)(\2)[ \t]*[=:][ \t]*(['"]?)([\x21\x23-\x26\x28-\x7e]{6,})(\6))`,
			input:    `authtoken="s3kr3tvalue"`,
			ctxGroup: 0, keyGroup: 2, valGrp: 6,
			wantCtx: `authtoken="s3kr3tvalue"`, wantKey: "authtoken", wantVal: "s3kr3tvalue",
		},
		{
			name:     "token/c-family",
			pattern:  `(([a-z0-9_]{0,32}tok(en)?)[ \t]*=[ \t]*"([\x21\x23-\x26\x28-\x7e]{6,})")`,
			input:    `authtoken="s3kr3tvalue"`,
			ctxGroup: 0, keyGroup: 1, valGrp: 3,
			wantCtx: `authtoken="s3kr3tvalue"`, wantKey: "authtoken", wantVal: "s3kr3tvalue",
		},
		{
			name:     "password/null",
			pattern:  `((["']?)([a-z0-9_]{0,32}pass(w(ord)))(\2)[ \t]*[=:][ \t]*(['"]?)([\x21\x23-\x26\x28-\x7e]{6,})(?(7)\7|))`,
			input:    `password=Sup3rSekrit!`,
			ctxGroup: 0, keyGroup: 2, valGrp: 7,
			wantCtx: "password=Sup3rSekrit!", wantKey: "password", wantVal: "Sup3rSekrit!",
		},
		{
			name:     "sshpass",
			pattern:  `\b(sshpass .*-p\s?(['"]?)(\S+)(\2))`,
			input:    `sshpass -psuperSekr3t jeff@h.com`,
			ctxGroup: 0, keyGroup: -1, valGrp: 2,
			wantCtx: "sshpass -psuperSekr3t", wantKey: "", wantVal: "superSekr3t",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re, err := regexp2.Compile(tc.pattern, regexp2.IgnoreCase)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			re.MatchTimeout = time.Second
			m, err := re.FindStringMatch(tc.input)
			if err != nil || m == nil {
				t.Fatalf("no match on %q (err=%v)", tc.input, err)
			}
			got := func(configGroup int) string {
				if configGroup < 0 {
					return ""
				}
				g := m.GroupByNumber(configGroup + 1) // the +1 convention
				if g == nil || len(g.Captures) == 0 {
					return ""
				}
				return g.String()
			}
			if v := got(tc.ctxGroup); v != tc.wantCtx {
				t.Errorf("context: got %q want %q", v, tc.wantCtx)
			}
			if v := got(tc.keyGroup); v != tc.wantKey {
				t.Errorf("key: got %q want %q", v, tc.wantKey)
			}
			if v := got(tc.valGrp); v != tc.wantVal {
				t.Errorf("value: got %q want %q", v, tc.wantVal)
			}
		})
	}
}
