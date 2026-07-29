# DataRake Go Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the `master` branch of datarake from Python to Go under `./golang`, preserving the `datarake.yaml` configuration syntax and the JSON/CSV output formats.

**Architecture:** One Go file per Python class (18 files), grouped into packages `match`, `filter`, `rake`, `rakeset`, `walker`, `writer`, `config`, `cmd/datarake`. The `Rake`↔`RakeMatch` circular dependency is broken by a `match.RakeInfo` interface, so dependency flow is acyclic: `match ← filter ← rake ← rakeset ← config ← cmd`. Parallelism moves from `ThreadPoolExecutor` to one goroutine per file bounded by a semaphore, with the main goroutine draining a FIFO oldest-first so output follows directory-walk order.

**Tech Stack:** Go 1.22, `github.com/dlclark/regexp2` (backreferences + conditional groups + rune offsets), `gopkg.in/yaml.v3`, `github.com/saintfish/chardet` + `golang.org/x/text` (encoding detection/decode), `github.com/spf13/pflag` (argparse-compatible CLI).

**Spec:** `docs/superpowers/specs/2026-07-29-datarake-golang-port-design.md`

## Global Constraints

- **Go version floor:** `go 1.22` in `go.mod`. Toolchain present is `go1.22.2`.
- **Module path:** `github.com/jcwoods/datarake/golang`.
- **Dependencies — these five only.** Do not add others without amending this plan:
  `github.com/dlclark/regexp2 v1.12.0`, `gopkg.in/yaml.v3`, `github.com/saintfish/chardet`, `golang.org/x/text`, `github.com/spf13/pflag`.
- **Regex engine is `regexp2`, never stdlib `regexp`.** Stdlib cannot express the config's backreferences or conditional groups, and it indexes in bytes rather than runes, which would silently corrupt the `offset`/`length` output fields on non-ASCII lines.
- **Every compiled pattern gets `re.MatchTimeout = matchTimeout`** (default 1s, `--match-timeout`). `regexp2` backtracks; this bounds it.
- **Python `re.match` is anchored at position 0, `re.search` is not.** Where the Python calls `.match()`, wrap the pattern as `\A(?:<pattern>)`. Where it calls `.search()` or `.finditer()`, do not.
- **Config group numbers are 0-based into a `findall` tuple that omits group 0.** Config group *k* is regex group *k+1*. Never "fix" this translation — it is correct for `auth url`, `auth token`, `private key`, all four `sensitive environment variable` contexts, `RakeHostname`, and `RakeEmail`.
- **The `datarake.yaml` schema does not change.** No new keys, no renamed keys, no removed keys. Only pattern text and group *numbers* change, exactly as enumerated in Task 1.
- **Output field order is fixed** (`common.py:157`): `file, line, label, severity, description, key_offset, key_length, key, value_offset, value_length, value, context_offset, context_length, context`. `key_offset`, `key_length`, `key` default to disabled.
- **JSON key order is fixed** (`common.py:396`): `path, line, type, description, severity, context, value`. Emit field-by-field; never marshal a Go `map` (Go sorts map keys).
- **Only the main goroutine may touch a writer.** Workers compute and return; they never emit.
- **No `panic` in library code.** Return errors. `MustCompile` is acceptable only in tests.
- **SARIF is out of scope.** Do not create `writer/sarifwriter.go`.
- **`entropy.py` is out of scope.** Do not port it.

## File Structure

| File | Responsibility |
|---|---|
| `golang/go.mod`, `go.sum` | Module + pinned deps |
| `golang/Makefile` | build, test, race, vet, fmt, lint, tidy, clean, install, cross |
| `golang/datarake.yaml` | Corrected config, `go:embed`-ed as the default |
| `golang/match/rakematch.go` | `RakeMatch`, `RakeInfo`, `OutputConfig`, `Field` |
| `golang/filter/rakefilter.go` | `RakeFilter` interface + `Load` dispatch + config coercion helpers |
| `golang/filter/literalfilter.go` | `LiteralFilter` |
| `golang/filter/regexfilter.go` | `RegexFilter` |
| `golang/filter/filterregistry.go` | `FilterRegistry` |
| `golang/walker/directorywalker.go` | `DirectoryWalker`, `Context` |
| `golang/rake/rake.go` | `Rake` base, `RelPath`, `Filterer`/`ContentRake`/`MetaRake` interfaces |
| `golang/rake/rakepattern.go` | `Pattern` — group translation, self-dispatch filtering |
| `golang/rake/rakefilemeta.go` | `FileMeta` |
| `golang/rake/rakecontextpattern.go` | `ContextPattern` — routes by file extension |
| `golang/rake/rakehostname.go` | `Hostname`, `IsValidHostname`, `DefaultTLDs` |
| `golang/rake/rakeemail.go` | `Email` |
| `golang/rake/rakebasicauth.go` | `BasicAuth` |
| `golang/rake/rakejwtauth.go` | `JWTAuth` |
| `golang/rakeset/rakeset.go` | `RakeSet`, `Stats`, `Scan`, encoding detection, universal newlines |
| `golang/writer/datarakewriter.go` | `DataRakeWriter` interface |
| `golang/writer/csvwriter.go` | `CSVWriter` + Python-compatible CSV quoting |
| `golang/writer/jsonwriter.go` | `JSONWriter` + Python-compatible JSON escaping |
| `golang/config/config.go` | `Load`, filter-registry construction, `Global`/`DirectoryWalker` wiring |
| `golang/cmd/datarake/main.go` | Flags, goroutine pipeline, totals |
| `golang/README.md` | Build/run/differences-from-Python |

---

### Task 1: Module scaffold, Makefile, and corrected `datarake.yaml`

This task front-loads the riskiest verification in the port: that every pattern in the corrected config compiles under `regexp2` and that the corrected group numbers resolve to the intended substrings. Everything else depends on that being true.

**Files:**
- Create: `golang/go.mod`, `golang/Makefile`, `golang/datarake.yaml`, `golang/embed.go`
- Test: `golang/config_patterns_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `golang/datarake.yaml` (corrected config); `embed.go` exporting `var DefaultConfig []byte` in package `datarake`.

- [ ] **Step 1: Create the module and pin dependencies**

```bash
mkdir -p golang && cd golang
cat > go.mod <<'EOF'
module github.com/jcwoods/datarake/golang

go 1.22
EOF
go get github.com/dlclark/regexp2@v1.12.0
go get gopkg.in/yaml.v3
go get github.com/saintfish/chardet
go get golang.org/x/text
go get github.com/spf13/pflag
```

- [ ] **Step 2: Copy the config and apply the corrections**

Copy `datarake/datarake.yaml` to `golang/datarake.yaml`, then make exactly these edits. Nothing else in the file changes.

**2a — brace shorthand.** `regexp2` uses .NET semantics where `{,32}` is a *literal*, not `{0,32}`. Six occurrences:

| Search | Replace |
|---|---|
| `[a-z0-9_]{,32}tok` | `[a-z0-9_]{0,32}tok` |
| `'^.{,5}$'` | `'^.{0,5}$'` |
| `(\S{,32}pass(w(ord)?)?)\s*=\s*"` | `(\S{0,32}pass(w(ord)?)?)\s*=\s*"` |
| `(\S{,32}pass(w(ord)?)?)\s*=\s*(["'']` | `(\S{0,32}pass(w(ord)?)?)\s*=\s*(["''` |
| `(\S{,32}pass(w(ord)?)?)\s*:\s*` | `(\S{0,32}pass(w(ord)?)?)\s*:\s*` |
| `(\S{,32}"pass(w(ord)?)?)"` | `(\S{0,32}"pass(w(ord)?)?)"` |

Verify none remain: `grep -c '{,' golang/datarake.yaml` must print `0`.

**2b — `token` rake, null context.** Change the trailing `(\5)` to `(\6)` so the context closes the *value* quote rather than echoing the *key* quote group, and correct all three group numbers:

```yaml
  - context: null
    pattern: '((["'']?)([a-z0-9_]{0,32}tok(en)?)(\2)[ \t]*[=:][ \t]*([''"]?)([\x21\x23-\x26\x28-\x7e]{6,})(\6))'
    keygroup:     2      # was 3
    valgroup:     6      # was 7
    contextgroup: 0      # was 1
```

**2c — `token` rake, c-family context.** Group numbers only:

```yaml
    keygroup:     1      # was 2
    valgroup:     3      # unchanged
    contextgroup: 0      # was 1
```

**2d — `token` rake, js/ts/py context.** Group numbers only:

```yaml
    keygroup:     1      # was 2
    valgroup:     4      # unchanged
    contextgroup: 0      # was 1
```

**2e — `password` rake, null context.** Group numbers only:

```yaml
    keygroup:     2      # was 3
    valgroup:     7      # unchanged
    contextgroup: 0      # was 1
```

**2f — `sshpass` rake.** Add an outer capture group spanning the whole match and renumber the backreference. `contextgroup: 0` and `valgroup: 2` then become correct without further edit:

```yaml
  pattern: '\b(sshpass .*-p\s?([\''"]?)(\S+)(\2))'
```

- [ ] **Step 3: Write the failing test**

`golang/config_patterns_test.go` — package `datarake`. This proves both that every pattern compiles under `regexp2` and that the corrected group numbers land on the intended text.

```go
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
		name                        string
		pattern                     string
		input                       string
		ctxGroup, keyGroup, valGrp  int // config-level numbers
		wantCtx, wantKey, wantVal   string
	}{
		{
			name:    "token/null",
			pattern: `((["']?)([a-z0-9_]{0,32}tok(en)?)(\2)[ \t]*[=:][ \t]*(['"]?)([\x21\x23-\x26\x28-\x7e]{6,})(\6))`,
			input:   `authtoken="s3kr3tvalue"`,
			ctxGroup: 0, keyGroup: 2, valGrp: 6,
			wantCtx: `authtoken="s3kr3tvalue"`, wantKey: "authtoken", wantVal: "s3kr3tvalue",
		},
		{
			name:    "token/c-family",
			pattern: `(([a-z0-9_]{0,32}tok(en)?)[ \t]*=[ \t]*"([\x21\x23-\x26\x28-\x7e]{6,})")`,
			input:   `authtoken="s3kr3tvalue"`,
			ctxGroup: 0, keyGroup: 1, valGrp: 3,
			wantCtx: `authtoken="s3kr3tvalue"`, wantKey: "authtoken", wantVal: "s3kr3tvalue",
		},
		{
			name:    "password/null",
			pattern: `((["']?)([a-z0-9_]{0,32}pass(w(ord)))(\2)[ \t]*[=:][ \t]*(['"]?)([\x21\x23-\x26\x28-\x7e]{6,})(?(7)\7|))`,
			input:   `password=Sup3rSekrit!`,
			ctxGroup: 0, keyGroup: 2, valGrp: 7,
			wantCtx: "password=Sup3rSekrit!", wantKey: "password", wantVal: "Sup3rSekrit!",
		},
		{
			name:    "sshpass",
			pattern: `\b(sshpass .*-p\s?(['"]?)(\S+)(\2))`,
			input:   `sshpass -psuperSekr3t jeff@h.com`,
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
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd golang && go test ./... -run 'TestEveryConfigPattern|TestNoBrace|TestCorrectedGroup' -v`
Expected: FAIL — `undefined: DefaultConfig` (no `embed.go` yet).

- [ ] **Step 5: Create `embed.go`**

```go
// Package datarake embeds the default scanner configuration.
package datarake

import _ "embed"

// DefaultConfig is the configuration used when no -c/--config is supplied.
// It replaces the Python importlib.resources lookup in _default_config_text.
//
//go:embed datarake.yaml
var DefaultConfig []byte
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd golang && go test . -run 'TestEveryConfigPattern|TestNoBrace|TestCorrectedGroup' -v`
Expected: PASS, all four tests. If `TestCorrectedGroupNumbers/token/null` fails on context, the `(\5)`→`(\6)` edit in Step 2b was missed.

- [ ] **Step 7: Write the Makefile**

```makefile
BINARY  := datarake
BINDIR  := bin
PKG     := github.com/jcwoods/datarake/golang
VERSION := $(shell sed -n 's/^version=//p' ../project.properties)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: all build test race vet fmt fmt-check lint tidy clean install cross

all: build

build:
	@mkdir -p $(BINDIR)
	go build $(LDFLAGS) -o $(BINDIR)/$(BINARY) ./cmd/datarake

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

lint: vet fmt-check

tidy:
	go mod tidy

install:
	go install $(LDFLAGS) ./cmd/datarake

clean:
	rm -rf $(BINDIR)
	go clean -testcache

cross:
	@mkdir -p $(BINDIR)
	@for os in linux darwin windows; do \
	  for arch in amd64 arm64; do \
	    ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	    echo "building $$os/$$arch"; \
	    GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) \
	      -o $(BINDIR)/$(BINARY)-$$os-$$arch$$ext ./cmd/datarake || exit 1; \
	  done; \
	done
```

- [ ] **Step 8: Verify the Makefile**

Run: `cd golang && make test && make vet && make fmt-check`
Expected: tests PASS; `vet` and `fmt-check` silent. `make build` will fail until Task 16 creates `cmd/datarake` — that is expected now.

- [ ] **Step 9: Commit**

```bash
cd /home/jwoods/src/datarake
git add golang/go.mod golang/go.sum golang/Makefile golang/datarake.yaml \
        golang/embed.go golang/config_patterns_test.go
git commit -m "feat(golang): module scaffold, Makefile, corrected datarake.yaml

Corrects the rake group numbers that make master emit empty contexts for
every content finding and empty values for token/sshpass, converts the
five {,N} occurrences that regexp2 reads as literals, and fixes the token
rake's trailing backreference to close the value quote.

Tests assert every config pattern compiles under regexp2 and that the
corrected group numbers resolve to the intended substrings."
```

---

### Task 2: `match` package — `RakeMatch`, `RakeInfo`, `OutputConfig`

**Files:**
- Create: `golang/match/rakematch.go`
- Test: `golang/match/rakematch_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type RakeInfo interface { PType() string; PDesc() string; Severity() string }`
  - `type Field int` with constants `FieldFile, FieldLine, FieldLabel, FieldSeverity, FieldDescription, FieldKeyOffset, FieldKeyLength, FieldKey, FieldValueOffset, FieldValueLength, FieldValue, FieldContextOffset, FieldContextLength, FieldContext`
  - `func NewOutputConfig(secure, disableContext, disableValue bool) *OutputConfig`
  - `func (o *OutputConfig) Enabled(f Field) bool`, `func (o *OutputConfig) Header() []string`, `func (o *OutputConfig) Secure() bool`, `func (o *OutputConfig) DisableContext() bool`, `func (o *OutputConfig) DisableValue() bool`
  - `func New(r RakeInfo, file string, line *int) *RakeMatch`
  - `func (m *RakeMatch) SetKey(v string, offset, length int)`, `SetValue`, `SetContext` — same signature
  - `func (m *RakeMatch) File() string`, `Line() *int`, `Label() string`, `Description() string`, `Severity() string`
  - `func (m *RakeMatch) Key() *string`, `KeyOffset() *int`, `KeyLength() *int`
  - `func (m *RakeMatch) ValueOffset() *int`, `ValueLength() *int`, `func (m *RakeMatch) Value(o *OutputConfig) *string`
  - `func (m *RakeMatch) ContextOffset() *int`, `ContextLength() *int`, `func (m *RakeMatch) Context(o *OutputConfig) *string`
  - `func (m *RakeMatch) SecureContext() string`
  - `func (m *RakeMatch) AsRecord(o *OutputConfig) []string`
  - `func (m *RakeMatch) Equal(other *RakeMatch) bool`
  - `MatchGroups []string` exported field

- [ ] **Step 1: Write the failing test**

```go
package match

import "testing"

type fakeRake struct{ t, d, s string }

func (f fakeRake) PType() string    { return f.t }
func (f fakeRake) PDesc() string    { return f.d }
func (f fakeRake) Severity() string { return f.s }

func intp(i int) *int { return &i }

func TestDefaultHeaderOrderAndDisabledKeyFields(t *testing.T) {
	o := NewOutputConfig(false, false, false)
	want := []string{
		"file", "line", "label", "severity", "description",
		"value_offset", "value_length", "value",
		"context_offset", "context_length", "context",
	}
	got := o.Header()
	if len(got) != len(want) {
		t.Fatalf("header len: got %d %v want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("header[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSecureThenDisableContextOrdering(t *testing.T) {
	// set_secure enables the context field; a later disable_context must win.
	o := NewOutputConfig(true, true, false)
	if o.Enabled(FieldContext) {
		t.Error("disable_context must override set_secure's fields['context']=True")
	}
	if o.Enabled(FieldValue) {
		t.Error("secure mode must disable the value field")
	}
}

func TestSecureModeContextIsHash(t *testing.T) {
	o := NewOutputConfig(true, false, false)
	m := New(fakeRake{"password", "desc", "HIGH"}, "a/b.txt", intp(2))
	m.SetContext("password=hunter2", 0, 16)
	got := m.Context(o)
	if got == nil {
		t.Fatal("context must be present in secure mode")
	}
	if len(*got) != 32 {
		t.Errorf("secure context must be a 32-char md5 hex digest, got %q", *got)
	}
	if *got == "password=hunter2" {
		t.Error("secure mode leaked the plaintext context")
	}
}

func TestAsRecordRendersNilAsEmptyAndIntsAsDigits(t *testing.T) {
	o := NewOutputConfig(false, false, false)
	// filemeta matches carry no line and no value/context.
	m := New(fakeRake{"ssh identity file", "d", "HIGH"}, "id_rsa", nil)
	rec := m.AsRecord(o)
	if rec[0] != "id_rsa" {
		t.Errorf("file: got %q", rec[0])
	}
	if rec[1] != "" {
		t.Errorf("nil line must render as empty string, got %q", rec[1])
	}
	m2 := New(fakeRake{"password", "d", "HIGH"}, "f", intp(7))
	m2.SetValue("hunter2", 9, 7)
	rec2 := m2.AsRecord(o)
	if rec2[1] != "7" {
		t.Errorf("line: got %q want \"7\"", rec2[1])
	}
	if rec2[5] != "9" || rec2[6] != "7" || rec2[7] != "hunter2" {
		t.Errorf("value triple: got %q,%q,%q", rec2[5], rec2[6], rec2[7])
	}
}

func TestUnsetGroupsReturnNil(t *testing.T) {
	o := NewOutputConfig(false, false, false)
	m := New(fakeRake{"t", "d", "LOW"}, "f", intp(1))
	if m.Value(o) != nil || m.ValueOffset() != nil || m.ValueLength() != nil {
		t.Error("unset value must report nil, not zero")
	}
	if m.Key() != nil {
		t.Error("unset key must report nil")
	}
	if m.SecureContext() != "" {
		t.Error("SecureContext with no context must be empty")
	}
}

func TestSetKeyLengthDefaultsToRuneLength(t *testing.T) {
	m := New(fakeRake{"t", "d", "LOW"}, "f", intp(1))
	m.SetKey("héllo", 3, -1) // -1 means "derive from the value"
	if got := m.KeyLength(); got == nil || *got != 5 {
		t.Errorf("length must be in runes (5), got %v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./match/ -v`
Expected: FAIL — `undefined: NewOutputConfig`, `undefined: New`.

- [ ] **Step 3: Write the implementation**

```go
// Package match holds RakeMatch, the record produced for every finding, plus
// the output-field configuration that controls how it is rendered.
package match

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
)

// RakeInfo is the subset of a Rake that a RakeMatch needs. Declaring it here
// rather than importing the rake package breaks the Rake<->RakeMatch cycle
// that Python resolves with the forward declaration at common.py:13.
type RakeInfo interface {
	PType() string
	PDesc() string
	Severity() string
}

// Field identifies an output column. Order matches common.py:157.
type Field int

const (
	FieldFile Field = iota
	FieldLine
	FieldLabel
	FieldSeverity
	FieldDescription
	FieldKeyOffset
	FieldKeyLength
	FieldKey
	FieldValueOffset
	FieldValueLength
	FieldValue
	FieldContextOffset
	FieldContextLength
	FieldContext
)

var fieldOrder = []Field{
	FieldFile, FieldLine, FieldLabel, FieldSeverity, FieldDescription,
	FieldKeyOffset, FieldKeyLength, FieldKey,
	FieldValueOffset, FieldValueLength, FieldValue,
	FieldContextOffset, FieldContextLength, FieldContext,
}

var fieldNames = map[Field]string{
	FieldFile: "file", FieldLine: "line", FieldLabel: "label",
	FieldSeverity: "severity", FieldDescription: "description",
	FieldKeyOffset: "key_offset", FieldKeyLength: "key_length", FieldKey: "key",
	FieldValueOffset: "value_offset", FieldValueLength: "value_length", FieldValue: "value",
	FieldContextOffset: "context_offset", FieldContextLength: "context_length", FieldContext: "context",
}

// OutputConfig is the immutable replacement for RakeMatch's mutable class
// globals (_secure, _disable_context, _disable_value, _has_been_read, fields).
// Those were written on every attribute read, which is a data race once files
// are scanned concurrently. Built once in main, then read-only.
type OutputConfig struct {
	secure         bool
	disableContext bool
	disableValue   bool
	enabled        map[Field]bool
}

// NewOutputConfig applies the three mutators in the same order main() does
// (secure, then disable_context, then disable_value) because they overlap:
// set_secure enables the context field and a later disable_context must win.
func NewOutputConfig(secure, disableContext, disableValue bool) *OutputConfig {
	o := &OutputConfig{
		secure:         secure,
		disableContext: disableContext,
		disableValue:   disableValue,
		enabled:        make(map[Field]bool, len(fieldOrder)),
	}
	for _, f := range fieldOrder {
		o.enabled[f] = true
	}
	// key_offset, key_length and key default off (common.py:162-164).
	o.enabled[FieldKeyOffset] = false
	o.enabled[FieldKeyLength] = false
	o.enabled[FieldKey] = false

	if secure { // set_secure
		o.enabled[FieldContext] = true
		o.enabled[FieldValue] = false
	}
	if disableContext { // disable_context
		o.enabled[FieldContextOffset] = false
		o.enabled[FieldContextLength] = false
		o.enabled[FieldContext] = false
	}
	if disableValue { // disable_value
		o.enabled[FieldValueOffset] = false
		o.enabled[FieldValueLength] = false
		o.enabled[FieldValue] = false
	}
	return o
}

func (o *OutputConfig) Enabled(f Field) bool { return o.enabled[f] }
func (o *OutputConfig) Secure() bool         { return o.secure }
func (o *OutputConfig) DisableContext() bool { return o.disableContext }
func (o *OutputConfig) DisableValue() bool   { return o.disableValue }

// Header returns the enabled column names in output order.
func (o *OutputConfig) Header() []string {
	out := make([]string, 0, len(fieldOrder))
	for _, f := range fieldOrder {
		if o.enabled[f] {
			out = append(out, fieldNames[f])
		}
	}
	return out
}

// span is one of the three (offset, length, value) triples. set distinguishes
// "captured the empty string" from "did not participate", which Python
// represents as "" versus None.
type span struct {
	offset int
	length int
	value  string
	set    bool
}

// RakeMatch records one finding. Offsets and lengths are measured in
// characters (runes), not bytes -- regexp2 indexes in runes, matching Python.
type RakeMatch struct {
	label       string
	description string
	severity    string
	file        string
	line        *int

	key     span
	value   span
	context span

	// MatchGroups mirrors Python's m.groups(default=''): every regex group
	// 1..N, with "" for groups that did not participate. Filters unpack it.
	MatchGroups []string
}

func New(r RakeInfo, file string, line *int) *RakeMatch {
	return &RakeMatch{
		label:       r.PType(),
		description: r.PDesc(),
		severity:    r.Severity(),
		file:        file,
		line:        line,
	}
}

// setSpan stores a triple. A negative length means "derive from value", in
// runes, matching Python's len() on a str.
func setSpan(s *span, v string, offset, length int) {
	if length < 0 {
		length = len([]rune(v))
	}
	*s = span{offset: offset, length: length, value: v, set: true}
}

// SetKey records the key. The key is used almost exclusively for filtering and
// is not output by default.
func (m *RakeMatch) SetKey(v string, offset, length int)     { setSpan(&m.key, v, offset, length) }
func (m *RakeMatch) SetValue(v string, offset, length int)   { setSpan(&m.value, v, offset, length) }
func (m *RakeMatch) SetContext(v string, offset, length int) { setSpan(&m.context, v, offset, length) }

func (m *RakeMatch) File() string        { return m.file }
func (m *RakeMatch) Line() *int          { return m.line }
func (m *RakeMatch) Label() string       { return m.label }
func (m *RakeMatch) Description() string { return m.description }
func (m *RakeMatch) Severity() string    { return m.severity }

func offsetOf(s span) *int {
	if !s.set {
		return nil
	}
	v := s.offset
	return &v
}

func lengthOf(s span) *int {
	if !s.set {
		return nil
	}
	v := s.length
	return &v
}

func (m *RakeMatch) Key() *string {
	if !m.key.set {
		return nil
	}
	v := m.key.value
	return &v
}
func (m *RakeMatch) KeyOffset() *int { return offsetOf(m.key) }
func (m *RakeMatch) KeyLength() *int { return lengthOf(m.key) }

func (m *RakeMatch) ValueOffset() *int { return offsetOf(m.value) }
func (m *RakeMatch) ValueLength() *int { return lengthOf(m.value) }

// Value returns nil in secure mode so no secret is ever rendered.
func (m *RakeMatch) Value(o *OutputConfig) *string {
	if o.Secure() || !m.value.set {
		return nil
	}
	v := m.value.value
	return &v
}

func (m *RakeMatch) ContextOffset() *int { return offsetOf(m.context) }
func (m *RakeMatch) ContextLength() *int { return lengthOf(m.context) }

// Context returns the md5 tracking hash instead of the literal text in secure
// mode, so a secret can still be followed as it moves within a file.
func (m *RakeMatch) Context(o *OutputConfig) *string {
	if !m.context.set {
		return nil
	}
	if o.Secure() {
		v := m.SecureContext()
		return &v
	}
	v := m.context.value
	return &v
}

// SecureContext hashes the file name and the literal context together.
func (m *RakeMatch) SecureContext() string {
	if !m.context.set {
		return ""
	}
	h := md5.New()
	h.Write([]byte(m.file))
	h.Write([]byte{0x00})
	h.Write([]byte(m.context.value))
	return hex.EncodeToString(h.Sum(nil))
}

// AsRecord renders the enabled fields in order for CSV. A nil value becomes
// the empty field, matching how csv.writer renders Python's None.
func (m *RakeMatch) AsRecord(o *OutputConfig) []string {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	num := func(p *int) string {
		if p == nil {
			return ""
		}
		return strconv.Itoa(*p)
	}

	out := make([]string, 0, len(fieldOrder))
	for _, f := range fieldOrder {
		if !o.enabled[f] {
			continue
		}
		switch f {
		case FieldFile:
			out = append(out, m.file)
		case FieldLine:
			out = append(out, num(m.line))
		case FieldLabel:
			out = append(out, m.label)
		case FieldSeverity:
			out = append(out, m.severity)
		case FieldDescription:
			out = append(out, m.description)
		case FieldKeyOffset:
			out = append(out, num(m.KeyOffset()))
		case FieldKeyLength:
			out = append(out, num(m.KeyLength()))
		case FieldKey:
			out = append(out, str(m.Key()))
		case FieldValueOffset:
			out = append(out, num(m.ValueOffset()))
		case FieldValueLength:
			out = append(out, num(m.ValueLength()))
		case FieldValue:
			out = append(out, str(m.Value(o)))
		case FieldContextOffset:
			out = append(out, num(m.ContextOffset()))
		case FieldContextLength:
			out = append(out, num(m.ContextLength()))
		case FieldContext:
			if o.DisableContext() {
				out = append(out, "")
				continue
			}
			out = append(out, str(m.Context(o)))
		}
	}
	return out
}

// Equal mirrors RakeMatch.__eq__: offsets and values of value/context must
// agree, as must label, description, severity, file and line. Lengths are
// deliberately not compared (common.py:219,226).
func (m *RakeMatch) Equal(other *RakeMatch) bool {
	if other == nil {
		return false
	}
	eqSpan := func(a, b span) bool {
		if a.set != b.set {
			return false
		}
		if !a.set {
			return true
		}
		return a.offset == b.offset && a.value == b.value
	}
	if !eqSpan(m.value, other.value) || !eqSpan(m.context, other.context) {
		return false
	}
	if m.label != other.label || m.description != other.description ||
		m.severity != other.severity || m.file != other.file {
		return false
	}
	switch {
	case m.line == nil && other.line == nil:
		return true
	case m.line == nil || other.line == nil:
		return false
	default:
		return *m.line == *other.line
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./match/ -v`
Expected: PASS, all six tests.

- [ ] **Step 5: Commit**

```bash
git add golang/match/
git commit -m "feat(golang): add match package with RakeMatch and OutputConfig

Replaces RakeMatch's mutable class globals with an immutable OutputConfig
built once in main. Those globals were written on every attribute read via
_has_been_read, which becomes a data race once files scan concurrently.
Breaks the Rake<->RakeMatch cycle with a RakeInfo interface."
```

---

### Task 3: `filter` package — `RakeFilter`, `LiteralFilter`, `RegexFilter`

**Files:**
- Create: `golang/filter/rakefilter.go`, `golang/filter/literalfilter.go`, `golang/filter/regexfilter.go`
- Test: `golang/filter/literalfilter_test.go`, `golang/filter/regexfilter_test.go`

**Interfaces:**
- Consumes: `match.RakeMatch`, `match.NewOutputConfig` (Task 2).
- Produces:
  - `type RakeFilter interface { Match(*match.RakeMatch) bool; String() string }`
  - `func Load(cfg map[string]any, timeout time.Duration) (RakeFilter, error)`
  - `func NewLiteralFilter(key, val *string, ignorecase bool) (*LiteralFilter, error)`
  - `func NewRegexFilter(key, val *string, ignorecase bool, timeout time.Duration) (*RegexFilter, error)`
  - Helpers: `func cfgString(cfg map[string]any, k string) *string`, `func cfgBool(cfg map[string]any, k string) bool`

**Critical fidelity note.** `RakeRegexFilter.match` (common.py:813,817) does `str(match.value)` with **no nil check**, so when the value is unset Python tests the pattern against the literal string `"None"`. `RakeLiteralFilter.match` *does* check and returns `false`. This asymmetry is real and changes which findings survive — preserve both behaviors exactly and comment them.

- [ ] **Step 1: Write the failing tests**

```go
package filter

import (
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

type fakeRake struct{}

func (fakeRake) PType() string    { return "t" }
func (fakeRake) PDesc() string    { return "d" }
func (fakeRake) Severity() string { return "LOW" }

func sp(s string) *string { return &s }
func line1() *int         { i := 1; return &i }

func withValue(v string) *match.RakeMatch {
	m := match.New(fakeRake{}, "f", line1())
	m.SetValue(v, 0, -1)
	return m
}

func withKey(k string) *match.RakeMatch {
	m := match.New(fakeRake{}, "f", line1())
	m.SetKey(k, 0, -1)
	return m
}

func TestLiteralFilterMatchesValue(t *testing.T) {
	f, err := NewLiteralFilter(nil, sp("password"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(withValue("password")) {
		t.Error("expected match")
	}
	if f.Match(withValue("hunter2")) {
		t.Error("expected no match")
	}
}

func TestLiteralFilterIgnorecase(t *testing.T) {
	f, _ := NewLiteralFilter(nil, sp("PASSWORD"), true)
	if !f.Match(withValue("password")) {
		t.Error("ignorecase must fold both sides")
	}
}

func TestLiteralFilterUnsetValueReturnsFalse(t *testing.T) {
	f, _ := NewLiteralFilter(nil, sp("password"), false)
	m := match.New(fakeRake{}, "f", line1()) // no value set
	if f.Match(m) {
		t.Error("literal filter must return false when the value is unset")
	}
}

func TestLiteralFilterRequiresKeyOrValue(t *testing.T) {
	if _, err := NewLiteralFilter(nil, nil, false); err == nil {
		t.Error("expected an error when neither key nor value is set")
	}
}

func TestRegexFilterIsAnchoredAtStart(t *testing.T) {
	// Python uses re.match, which anchors at position 0 but not at the end.
	f, err := NewRegexFilter(nil, sp(`\$[a-z_]+`), true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(withValue("$FOO_BAR trailing")) {
		t.Error("re.match semantics: must match at position 0 without an end anchor")
	}
	if f.Match(withValue("prefix $FOO")) {
		t.Error("re.match semantics: must not match mid-string")
	}
}

// Preserves the str(None) behaviour at common.py:813. RakeRegexFilter does not
// nil-check the value, so an unset value is tested against the text "None".
func TestRegexFilterUnsetValueTestsAgainstLiteralNone(t *testing.T) {
	f, _ := NewRegexFilter(nil, sp(`^.{0,5}$`), false, time.Second)
	m := match.New(fakeRake{}, "f", line1()) // no value set
	if !f.Match(m) {
		t.Error(`unset value must be tested as the literal "None" (4 chars), matching ^.{0,5}$`)
	}
}

func TestRegexFilterKeyPattern(t *testing.T) {
	f, _ := NewRegexFilter(sp(`("?)[Pp]ublicKeyToken(\1)`), nil, false, time.Second)
	if !f.Match(withKey(`"PublicKeyToken"`)) {
		t.Error("backreference in a key filter must work under regexp2")
	}
	if f.Match(withKey("authtoken")) {
		t.Error("expected no match")
	}
}

func TestLoadDispatchesByType(t *testing.T) {
	lf, err := Load(map[string]any{"type": "literal", "value": "ENCRYPTED"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lf.(*LiteralFilter); !ok {
		t.Errorf("type literal must build a LiteralFilter, got %T", lf)
	}
	rf, err := Load(map[string]any{"type": "regex", "value": `^\$[a-z]+$`, "ignorecase": true}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rf.(*RegexFilter); !ok {
		t.Errorf("type regex must build a RegexFilter, got %T", rf)
	}
}

func TestLoadRejectsReferenceTypesAndUnknowns(t *testing.T) {
	for _, tc := range []string{"named", "set", "bogus"} {
		if _, err := Load(map[string]any{"type": tc, "name": "X"}, time.Second); err == nil {
			t.Errorf("type %q must be rejected by Load (needs a FilterRegistry, or is invalid)", tc)
		}
	}
	if _, err := Load(map[string]any{"value": "x"}, time.Second); err == nil {
		t.Error("a missing type must be rejected")
	}
}

// A null key/value in YAML must read as absent, not as the string "null".
func TestNullConfigValuesAreAbsent(t *testing.T) {
	f, err := Load(map[string]any{
		"type": "regex", "key": nil, "value": `^\$[a-z0-9_]+$`, "ignorecase": true,
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(withValue("$foo")) {
		t.Error("expected the value pattern to apply with a null key")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd golang && go test ./filter/ -v`
Expected: FAIL — `undefined: NewLiteralFilter`, `undefined: NewRegexFilter`, `undefined: Load`.

- [ ] **Step 3: Write `rakefilter.go`**

```go
// Package filter implements the denylist filters that suppress false-positive
// rake matches. A filter that matches means "discard this finding".
package filter

import (
	"fmt"
	"strings"
	"time"

	"github.com/jcwoods/datarake/golang/match"
)

// RakeFilter tests a match. Returning true means the match should be dropped.
// Implementations are read-only after construction, so a single instance is
// safe to share across rakes and across goroutines.
type RakeFilter interface {
	Match(m *match.RakeMatch) bool
	String() string
}

// cfgString reads an optional string. A YAML null, a missing key, or a
// non-string all read as absent.
func cfgString(cfg map[string]any, k string) *string {
	v, ok := cfg[k]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func cfgBool(cfg map[string]any, k string) bool {
	v, ok := cfg[k]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// Load builds a single inline filter. Reference types (named, set) need a
// FilterRegistry to resolve and are rejected here, matching RakeFilter.load.
func Load(cfg map[string]any, timeout time.Duration) (RakeFilter, error) {
	t := cfgString(cfg, "type")
	if t == nil {
		return nil, fmt.Errorf("filter type not specified")
	}

	key := cfgString(cfg, "key")
	val := cfgString(cfg, "value")
	ic := cfgBool(cfg, "ignorecase")

	switch strings.ToLower(*t) {
	case "regex":
		return NewRegexFilter(key, val, ic, timeout)
	case "literal":
		return NewLiteralFilter(key, val, ic)
	case "named", "set":
		name := ""
		if n := cfgString(cfg, "name"); n != nil {
			name = *n
		}
		return nil, fmt.Errorf("filter type %q requires a FilterRegistry to resolve (reference %q)", *t, name)
	default:
		return nil, fmt.Errorf("invalid filter type: %s", *t)
	}
}
```

- [ ] **Step 4: Write `literalfilter.go`**

```go
package filter

import (
	"fmt"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
)

// LiteralFilter compares the key and/or value for exact equality.
type LiteralFilter struct {
	key        *string
	val        *string
	ignorecase bool
}

func NewLiteralFilter(key, val *string, ignorecase bool) (*LiteralFilter, error) {
	if key == nil && val == nil {
		return nil, fmt.Errorf("one of key or value must be set for literal filter")
	}
	if ignorecase {
		if key != nil {
			k := strings.ToLower(*key)
			key = &k
		}
		if val != nil {
			v := strings.ToLower(*val)
			val = &v
		}
	}
	return &LiteralFilter{key: key, val: val, ignorecase: ignorecase}, nil
}

func (f *LiteralFilter) String() string {
	d := func(p *string) string {
		if p == nil {
			return "None"
		}
		return *p
	}
	return fmt.Sprintf("<RakeLiteralFilter(key=%s, val=%s)>", d(f.key), d(f.val))
}

// Match returns true when every configured side compares equal. Unlike
// RegexFilter, an unset key or value yields false (common.py:759,769).
func (f *LiteralFilter) Match(m *match.RakeMatch) bool {
	// A nil OutputConfig is not usable here; filters run before output is
	// configured, so read the raw value via a non-secure view.
	oc := plainOutput()

	if f.val != nil {
		v := m.Value(oc)
		if v == nil {
			return false
		}
		s := *v
		if f.ignorecase {
			s = strings.ToLower(s)
		}
		if s != *f.val {
			return false
		}
	}

	if f.key != nil {
		k := m.Key()
		if k == nil {
			return false
		}
		s := *k
		if f.ignorecase {
			s = strings.ToLower(s)
		}
		if s != *f.key {
			return false
		}
	}

	return true
}
```

- [ ] **Step 5: Write `regexfilter.go`**

```go
package filter

import (
	"fmt"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/match"
)

// plainOutput is a non-secure, nothing-disabled view used when filters need to
// read a match's raw value. Filtering happens before output is configured, and
// a filter must see the real secret to decide whether to suppress it.
var plainOutput = func() func() *match.OutputConfig {
	var once sync.Once
	var oc *match.OutputConfig
	return func() *match.OutputConfig {
		once.Do(func() { oc = match.NewOutputConfig(false, false, false) })
		return oc
	}
}()

// RegexFilter applies anchored patterns to the key and/or value.
type RegexFilter struct {
	key *regexp2.Regexp
	val *regexp2.Regexp
	src struct{ key, val string }
}

// NewRegexFilter compiles the patterns. Python uses re.match, which anchors at
// position 0 but not at the end, so each pattern is wrapped in \A(?:...).
func NewRegexFilter(key, val *string, ignorecase bool, timeout time.Duration) (*RegexFilter, error) {
	if key == nil && val == nil {
		return nil, fmt.Errorf("one of key or value must be set for regex filter")
	}

	opts := regexp2.None
	if ignorecase {
		opts = regexp2.IgnoreCase
	}

	f := &RegexFilter{}
	compile := func(p string) (*regexp2.Regexp, error) {
		re, err := regexp2.Compile(`\A(?:`+p+`)`, opts)
		if err != nil {
			return nil, fmt.Errorf("compile filter pattern %q: %w", p, err)
		}
		re.MatchTimeout = timeout
		return re, nil
	}

	if key != nil {
		re, err := compile(*key)
		if err != nil {
			return nil, err
		}
		f.key, f.src.key = re, *key
	}
	if val != nil {
		re, err := compile(*val)
		if err != nil {
			return nil, err
		}
		f.val, f.src.val = re, *val
	}
	return f, nil
}

func (f *RegexFilter) String() string {
	return fmt.Sprintf("<RakeRegexFilter(key=%s, val=%s)>", f.src.key, f.src.val)
}

// Match returns true when every configured pattern matches.
//
// Note the deliberate lack of a nil check on the value and key: Python does
// str(match.value) unconditionally (common.py:813,817), so an unset group is
// tested against the literal text "None". That changes which findings survive,
// so it is reproduced rather than corrected.
func (f *RegexFilter) Match(m *match.RakeMatch) bool {
	oc := plainOutput()

	pyStr := func(p *string) string {
		if p == nil {
			return "None"
		}
		return *p
	}

	if f.val != nil {
		ok, err := f.val.MatchString(pyStr(m.Value(oc)))
		if err != nil || !ok {
			return false
		}
	}
	if f.key != nil {
		ok, err := f.key.MatchString(pyStr(m.Key()))
		if err != nil || !ok {
			return false
		}
	}
	return true
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd golang && go test ./filter/ -v`
Expected: PASS, all nine tests.

- [ ] **Step 7: Commit**

```bash
git add golang/filter/rakefilter.go golang/filter/literalfilter.go \
        golang/filter/regexfilter.go golang/filter/literalfilter_test.go \
        golang/filter/regexfilter_test.go
git commit -m "feat(golang): add RakeFilter, LiteralFilter and RegexFilter

Filters are a denylist: a match means discard the finding. Regex patterns
are wrapped in \\A(?:...) to reproduce re.match's start anchoring.

Preserves two asymmetries from common.py: RegexFilter does not nil-check
the key/value and so tests an unset group against the literal \"None\",
while LiteralFilter checks and returns false. Both affect which findings
survive."
```

---

### Task 4: `filter` package — `FilterRegistry`

**Files:**
- Create: `golang/filter/filterregistry.go`
- Test: `golang/filter/filterregistry_test.go`

**Interfaces:**
- Consumes: `RakeFilter`, `Load`, `cfgString` (Task 3).
- Produces:
  - `func NewFilterRegistry() *FilterRegistry`
  - `func (r *FilterRegistry) RegisterNamed(name string, f RakeFilter) error`
  - `func (r *FilterRegistry) RegisterSet(name string, filters []RakeFilter) error`
  - `func (r *FilterRegistry) Load(cfg map[string]any, timeout time.Duration) (RakeFilter, error)`
  - `func (r *FilterRegistry) LoadList(cfgs []any, timeout time.Duration) ([]RakeFilter, error)`

- [ ] **Step 1: Write the failing test**

```go
package filter

import (
	"testing"
	"time"
)

func TestRegisterNamedRejectsDuplicates(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("x"), false)
	if err := r.RegisterNamed("A", f); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterNamed("A", f); err == nil {
		t.Error("duplicate NamedFilter name must be rejected")
	}
}

func TestNamedAndSetNamespacesCollide(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("x"), false)
	if err := r.RegisterNamed("A", f); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterSet("A", []RakeFilter{f}); err == nil {
		t.Error("a FilterSet must not reuse a NamedFilter's name")
	}
	r2 := NewFilterRegistry()
	if err := r2.RegisterSet("B", []RakeFilter{f}); err != nil {
		t.Fatal(err)
	}
	if err := r2.RegisterNamed("B", f); err == nil {
		t.Error("a NamedFilter must not reuse a FilterSet's name")
	}
}

func TestLoadResolvesNamedReference(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("ENCRYPTED"), false)
	r.RegisterNamed("Enc", f)

	got, err := r.Load(map[string]any{"type": "named", "name": "Enc"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != f {
		t.Error("a named reference must resolve to the shared instance")
	}
	if _, err := r.Load(map[string]any{"type": "named", "name": "Nope"}, time.Second); err == nil {
		t.Error("an unknown NamedFilter must error")
	}
	if _, err := r.Load(map[string]any{"type": "named"}, time.Second); err == nil {
		t.Error("a named reference without a name must error")
	}
}

func TestLoadRejectsSetWhereSingleFilterRequired(t *testing.T) {
	r := NewFilterRegistry()
	f, _ := NewLiteralFilter(nil, sp("x"), false)
	r.RegisterSet("S", []RakeFilter{f})
	if _, err := r.Load(map[string]any{"type": "set", "name": "S"}, time.Second); err == nil {
		t.Error("a FilterSet must be rejected where a single filter is required")
	}
}

func TestLoadListExpandsSetsInlinePreservingOrder(t *testing.T) {
	r := NewFilterRegistry()
	a, _ := NewLiteralFilter(nil, sp("a"), false)
	b, _ := NewLiteralFilter(nil, sp("b"), false)
	c, _ := NewLiteralFilter(nil, sp("c"), false)
	r.RegisterSet("AB", []RakeFilter{a, b})
	r.RegisterNamed("C", c)

	got, err := r.LoadList([]any{
		map[string]any{"type": "set", "name": "AB"},
		map[string]any{"type": "named", "name": "C"},
		map[string]any{"type": "literal", "value": "d"},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 filters after set expansion, got %d", len(got))
	}
	if got[0] != a || got[1] != b || got[2] != c {
		t.Error("set expansion must preserve order and share instances")
	}
}

func TestLoadListUnknownSetErrors(t *testing.T) {
	r := NewFilterRegistry()
	if _, err := r.LoadList([]any{map[string]any{"type": "set", "name": "Nope"}}, time.Second); err == nil {
		t.Error("an unknown FilterSet must error")
	}
	if _, err := r.LoadList([]any{map[string]any{"type": "set"}}, time.Second); err == nil {
		t.Error("a set reference without a name must error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./filter/ -run FilterRegistry -v` plus the `TestLoad*` names above.
Expected: FAIL — `undefined: NewFilterRegistry`.

- [ ] **Step 3: Write the implementation**

```go
package filter

import (
	"fmt"
	"strings"
	"time"
)

// FilterRegistry is the per-config registry of NamedFilters and FilterSets.
// A NamedFilter resolves to one RakeFilter; a FilterSet resolves to a list
// expanded inline wherever it is referenced. Sharing one instance across
// rakes is safe because filters are read-only after construction.
//
// Each config load builds its own registry, so multiple configurations can
// coexist (in tests, for instance) without cross-contamination.
type FilterRegistry struct {
	named map[string]RakeFilter
	sets  map[string][]RakeFilter
}

func NewFilterRegistry() *FilterRegistry {
	return &FilterRegistry{
		named: map[string]RakeFilter{},
		sets:  map[string][]RakeFilter{},
	}
}

func (r *FilterRegistry) RegisterNamed(name string, f RakeFilter) error {
	if _, dup := r.named[name]; dup {
		return fmt.Errorf("duplicate NamedFilter name: %q", name)
	}
	if _, clash := r.sets[name]; clash {
		return fmt.Errorf("name %q is already used by a FilterSet", name)
	}
	r.named[name] = f
	return nil
}

func (r *FilterRegistry) RegisterSet(name string, filters []RakeFilter) error {
	if _, dup := r.sets[name]; dup {
		return fmt.Errorf("duplicate FilterSet name: %q", name)
	}
	if _, clash := r.named[name]; clash {
		return fmt.Errorf("name %q is already used by a NamedFilter", name)
	}
	cp := make([]RakeFilter, len(filters))
	copy(cp, filters)
	r.sets[name] = cp
	return nil
}

// Load resolves a single-filter config, handling `type: named` lookups and
// delegating everything else. A `type: set` here is an error -- use LoadList,
// where sets can expand.
func (r *FilterRegistry) Load(cfg map[string]any, timeout time.Duration) (RakeFilter, error) {
	t := ""
	if s := cfgString(cfg, "type"); s != nil {
		t = strings.ToLower(*s)
	}

	switch t {
	case "named":
		name := cfgString(cfg, "name")
		if name == nil {
			return nil, fmt.Errorf("NamedFilter reference missing 'name'")
		}
		f, ok := r.named[*name]
		if !ok {
			return nil, fmt.Errorf("unknown NamedFilter: %q", *name)
		}
		return f, nil
	case "set":
		name := ""
		if s := cfgString(cfg, "name"); s != nil {
			name = *s
		}
		return nil, fmt.Errorf("FilterSet %q cannot be used where a single filter is required; use it in a filter list instead", name)
	default:
		return Load(cfg, timeout)
	}
}

// LoadList flattens filter-config entries into a filter list. Each entry may
// be an inline filter, a NamedFilter reference, or a FilterSet reference.
// FilterSet references expand inline; order is preserved.
func (r *FilterRegistry) LoadList(cfgs []any, timeout time.Duration) ([]RakeFilter, error) {
	out := make([]RakeFilter, 0, len(cfgs))

	for _, raw := range cfgs {
		cfg, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("filter list entries must be mappings, got %T", raw)
		}

		t := ""
		if s := cfgString(cfg, "type"); s != nil {
			t = strings.ToLower(*s)
		}

		if t == "set" {
			name := cfgString(cfg, "name")
			if name == nil {
				return nil, fmt.Errorf("FilterSet reference missing 'name'")
			}
			set, ok := r.sets[*name]
			if !ok {
				return nil, fmt.Errorf("unknown FilterSet: %q", *name)
			}
			out = append(out, set...)
			continue
		}

		f, err := r.Load(cfg, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}

	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./filter/ -v`
Expected: PASS, all tests from Tasks 3 and 4.

- [ ] **Step 5: Commit**

```bash
git add golang/filter/filterregistry.go golang/filter/filterregistry_test.go
git commit -m "feat(golang): add FilterRegistry for NamedFilter and FilterSet

Per-config registry. Named filters resolve to a shared instance; filter
sets expand inline in order. Named and set namespaces are disjoint."
```

---

### Task 5: `walker` package — `DirectoryWalker` and `Context`

**Files:**
- Create: `golang/walker/directorywalker.go`
- Test: `golang/walker/directorywalker_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Context struct { BasePath, Path, Filename, FullPath, FileType, Encoding string; HasFileType bool; LineNo *int }`
  - `func New(path string, excludeSubdirs []string, verbose bool) *DirectoryWalker`
  - `func (w *DirectoryWalker) Walk(fn func(*Context) error) error`
  - `var DefaultExcludeSubdirs = []string{".svn", ".git"}`

**Notes.** The extension rule has a quirk worth preserving: Python does
`parts = fnam.split("."); ext = parts[-1] if len(parts) > 1 else None`, so
`.gitignore` yields `FileType == "gitignore"` rather than no extension. A
callback rather than a channel avoids goroutine leaks on early return.
`filepath.WalkDir` sorts directory entries, unlike `os.walk`; that is delta 11
in the spec and is what makes golden-file tests viable.

- [ ] **Step 1: Write the failing test**

```go
package walker

import (
	"os"
	"path/filepath"
	"testing"
)

func mkTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("a.txt", "a")
	mk("sub/b.py", "b")
	mk("sub/deep/c", "c")
	mk(".git/config", "x")
	mk("__pycache__/d.pyc", "x")
	mk(".gitignore", "x")
	return root
}

func collect(t *testing.T, root string, excl []string) []*Context {
	t.Helper()
	var got []*Context
	if err := New(root, excl, false).Walk(func(c *Context) error {
		got = append(got, c)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWalkPrunesExcludedSubdirs(t *testing.T) {
	root := mkTree(t)
	for _, c := range collect(t, root, []string{".git", "__pycache__"}) {
		if filepath.Base(c.Path) == ".git" || filepath.Base(c.Path) == "__pycache__" {
			t.Errorf("excluded dir was walked: %s", c.FullPath)
		}
	}
}

func TestWalkYieldsFilesWithContextFields(t *testing.T) {
	root := mkTree(t)
	byName := map[string]*Context{}
	for _, c := range collect(t, root, DefaultExcludeSubdirs) {
		byName[c.Filename] = c
	}

	a, ok := byName["a.txt"]
	if !ok {
		t.Fatal("a.txt not yielded")
	}
	if a.BasePath != root {
		t.Errorf("BasePath: got %q want %q", a.BasePath, root)
	}
	if a.FullPath != filepath.Join(root, "a.txt") {
		t.Errorf("FullPath: got %q", a.FullPath)
	}
	if a.FileType != "txt" || !a.HasFileType {
		t.Errorf("FileType: got %q hasType=%v want \"txt\" true", a.FileType, a.HasFileType)
	}

	// No dot at all => no extension.
	if c := byName["c"]; c == nil {
		t.Fatal("sub/deep/c not yielded")
	} else if c.HasFileType {
		t.Errorf("a name with no dot must have no filetype, got %q", c.FileType)
	}

	// Preserved quirk: split(".") on ".gitignore" is ["", "gitignore"], so the
	// dotfile's own name becomes its extension.
	if g := byName[".gitignore"]; g == nil {
		t.Fatal(".gitignore not yielded")
	} else if !g.HasFileType || g.FileType != "gitignore" {
		t.Errorf("dotfile extension quirk: got %q hasType=%v want \"gitignore\" true", g.FileType, g.HasFileType)
	}
}

func TestWalkIsDeterministicallySorted(t *testing.T) {
	root := mkTree(t)
	first := collect(t, root, DefaultExcludeSubdirs)
	second := collect(t, root, DefaultExcludeSubdirs)
	if len(first) != len(second) {
		t.Fatalf("walk yielded %d then %d files", len(first), len(second))
	}
	for i := range first {
		if first[i].FullPath != second[i].FullPath {
			t.Fatalf("walk order not stable at %d: %q vs %q", i, first[i].FullPath, second[i].FullPath)
		}
	}
}

func TestWalkPropagatesCallbackError(t *testing.T) {
	root := mkTree(t)
	want := os.ErrClosed
	err := New(root, DefaultExcludeSubdirs, false).Walk(func(c *Context) error { return want })
	if err == nil {
		t.Fatal("callback error must propagate")
	}
}

func TestWalkOnSingleFileTarget(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "solo.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := collect(t, p, DefaultExcludeSubdirs)
	if len(got) != 1 || got[0].Filename != "solo.txt" {
		t.Fatalf("a file target must yield itself, got %#v", got)
	}
}

func TestWalkMissingPathErrors(t *testing.T) {
	if err := New(filepath.Join(t.TempDir(), "nope"), nil, false).Walk(func(*Context) error { return nil }); err == nil {
		t.Error("a nonexistent path must error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./walker/ -v`
Expected: FAIL — `undefined: New`, `undefined: Context`, `undefined: DefaultExcludeSubdirs`.

- [ ] **Step 3: Write the implementation**

```go
// Package walker enumerates the files to be scanned.
package walker

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultExcludeSubdirs matches DirectoryWalker.__init__ (common.py:31) and is
// used when the config supplies no DirectoryWalker.ExcludeSubdirs.
var DefaultExcludeSubdirs = []string{".svn", ".git"}

// Context describes one file to be scanned. Each Context is created here and
// owned exclusively by the goroutine scanning it, so no locking is needed.
type Context struct {
	BasePath string
	Path     string // directory holding the file
	Filename string // basename
	FullPath string
	FileType string // extension without the dot
	// HasFileType distinguishes "no extension" from "empty extension",
	// which Python represents as None versus "".
	HasFileType bool

	// Encoding is filled in by RakeSet.Scan once detected.
	Encoding string
	// LineNo is the 1-based line currently being scanned, nil outside content
	// scanning.
	LineNo *int
}

// DirectoryWalker recursively enumerates files below a base path, pruning
// excluded directories before descending into them.
type DirectoryWalker struct {
	basePath string
	exclude  map[string]struct{}
	verbose  bool
}

func New(path string, excludeSubdirs []string, verbose bool) *DirectoryWalker {
	if excludeSubdirs == nil {
		excludeSubdirs = DefaultExcludeSubdirs
	}
	ex := make(map[string]struct{}, len(excludeSubdirs))
	for _, d := range excludeSubdirs {
		ex[d] = struct{}{}
	}
	return &DirectoryWalker{basePath: path, exclude: ex, verbose: verbose}
}

// splitExt reproduces the Python rule: split on ".", take the last part only
// when there was at least one dot. ".gitignore" therefore reports the
// extension "gitignore".
func splitExt(name string) (string, bool) {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return "", false
	}
	return parts[len(parts)-1], true
}

// Walk invokes fn once per file, in sorted order. A callback rather than a
// channel keeps cancellation simple: returning an error stops the walk and
// leaves no goroutine behind.
func (w *DirectoryWalker) Walk(fn func(*Context) error) error {
	info, err := os.Stat(w.basePath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", w.basePath, err)
	}

	// A file target yields just itself; its directory becomes the base path so
	// relative reporting stays sensible.
	if !info.IsDir() {
		dir := filepath.Dir(w.basePath)
		return fn(w.newContext(dir, filepath.Base(w.basePath), dir))
	}

	return filepath.WalkDir(w.basePath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if w.verbose {
				fmt.Fprintf(os.Stderr, "* skipping %s: %v\n", p, err)
			}
			// A directory we cannot read is skipped, not fatal.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			// Prune before descending, matching the blacklist applied to
			// os.walk's dirnames at common.py:51.
			if p != w.basePath {
				if _, skip := w.exclude[d.Name()]; skip {
					return fs.SkipDir
				}
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		return fn(w.newContext(filepath.Dir(p), d.Name(), w.basePath))
	})
}

func (w *DirectoryWalker) newContext(dir, name, base string) *Context {
	ext, hasExt := splitExt(name)
	c := &Context{
		BasePath:    base,
		Path:        dir,
		Filename:    name,
		FullPath:    filepath.Join(dir, name),
		FileType:    ext,
		HasFileType: hasExt,
	}
	if w.verbose {
		fmt.Fprintf(os.Stderr, "* New context: %s\n", c.FullPath)
	}
	return c
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./walker/ -v`
Expected: PASS, all seven tests.

- [ ] **Step 5: Commit**

```bash
git add golang/walker/
git commit -m "feat(golang): add DirectoryWalker

Callback-based traversal with directory pruning applied before descent.
Preserves the Python extension rule, including the quirk that .gitignore
reports the extension 'gitignore'. Entries are sorted, unlike os.walk,
which makes output order reproducible across runs and machines."
```

---

### Task 6: `rake` package — `Rake` base, `RelPath`, and the rake interfaces

**Files:**
- Create: `golang/rake/rake.go`
- Test: `golang/rake/rake_test.go`

**Interfaces:**
- Consumes: `match.RakeInfo` (Task 2), `walker.Context` (Task 5).
- Produces:
  - `const PartContent = "content"`, `const PartFileMeta = "filemeta"`
  - `func NewRake(name, ptype, pdesc, severity, part string) (*Rake, error)`
  - `func (r *Rake) Name() string`, `PType()`, `PDesc()`, `Severity()`, `Part()`, `String()`
  - `func RelPath(basepath, fullpath string) string`
  - `type Filterer interface { Filter(*match.RakeMatch) bool }`
  - `type ContentRake interface { match.RakeInfo; Name() string; Part() string; Match(*walker.Context, string) ([]*match.RakeMatch, error); Filter(*match.RakeMatch) bool }`
  - `type MetaRake interface { match.RakeInfo; Name() string; Part() string; MatchContext(*walker.Context) (*match.RakeMatch, error) }`

- [ ] **Step 1: Write the failing test**

```go
package rake

import "testing"

func TestNewRakeRejectsInvalidPart(t *testing.T) {
	if _, err := NewRake("X", "t", "d", "LOW", "bogus"); err == nil {
		t.Error("an invalid part must be rejected")
	}
	for _, p := range []string{PartContent, PartFileMeta} {
		if _, err := NewRake("X", "t", "d", "LOW", p); err != nil {
			t.Errorf("part %q must be accepted: %v", p, err)
		}
	}
}

func TestRakeAccessors(t *testing.T) {
	r, err := NewRake("RakePattern", "password", "possible plaintext password", "HIGH", PartContent)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name() != "RakePattern" || r.PType() != "password" ||
		r.PDesc() != "possible plaintext password" || r.Severity() != "HIGH" ||
		r.Part() != PartContent {
		t.Errorf("accessor mismatch: %#v", r)
	}
}

func TestRakeString(t *testing.T) {
	r, _ := NewRake("RakePattern", "password", "d", "HIGH", PartContent)
	want := "<Rake(RakePattern, password, content)>"
	if got := r.String(); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRelPathStripsBasepathAndLeadingSlashes(t *testing.T) {
	cases := []struct{ base, full, want string }{
		{"/src", "/src/a/b.txt", "a/b.txt"},
		{"/src", "/src///a.txt", "a.txt"},
		{"", "a.txt", "a.txt"},
		{".", "./a.txt", "a.txt"},
		// Hardening: Python raises IndexError here (common.py:121).
		{"/src", "/src", ""},
		{"/src", "/src/", ""},
	}
	for _, tc := range cases {
		if got := RelPath(tc.base, tc.full); got != tc.want {
			t.Errorf("RelPath(%q,%q): got %q want %q", tc.base, tc.full, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./rake/ -v`
Expected: FAIL — `undefined: NewRake`, `undefined: PartContent`.

- [ ] **Step 3: Write the implementation**

```go
// Package rake implements the issue finders. A Rake is applied either to file
// metadata (once per file) or to content (once per line), producing RakeMatch
// records.
package rake

import (
	"fmt"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// The two places a rake can be applied.
const (
	PartContent  = "content"
	PartFileMeta = "filemeta"
)

// Filterer is implemented by anything that can suppress a match. Pattern holds
// one to reproduce Python's dynamic dispatch through self.filter(): Go
// embedding alone would always call the base implementation.
type Filterer interface {
	Filter(m *match.RakeMatch) bool
}

// ContentRake is applied once per line and returns every match on that line.
type ContentRake interface {
	match.RakeInfo
	Name() string
	Part() string
	Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error)
	Filter(m *match.RakeMatch) bool
}

// MetaRake is applied once per file and returns a single match or nil.
type MetaRake interface {
	match.RakeInfo
	Name() string
	Part() string
	MatchContext(ctx *walker.Context) (*match.RakeMatch, error)
}

// Rake carries the metadata shared by every rake type.
type Rake struct {
	name     string
	ptype    string
	pdesc    string
	severity string
	part     string
}

func NewRake(name, ptype, pdesc, severity, part string) (*Rake, error) {
	if part != PartContent && part != PartFileMeta {
		return nil, fmt.Errorf("invalid part in Rake initializer: %s", part)
	}
	return &Rake{name: name, ptype: ptype, pdesc: pdesc, severity: severity, part: part}, nil
}

func (r *Rake) Name() string     { return r.name }
func (r *Rake) PType() string    { return r.ptype }
func (r *Rake) PDesc() string    { return r.pdesc }
func (r *Rake) Severity() string { return r.severity }
func (r *Rake) Part() string     { return r.part }

func (r *Rake) String() string {
	return fmt.Sprintf("<Rake(%s, %s, %s)>", r.name, r.ptype, r.part)
}

// Filter is the fail-safe default: keep everything. Real filtering is
// implemented per rake type.
func (r *Rake) Filter(m *match.RakeMatch) bool { return true }

// RelPath strips the base path and any leading separators so findings are
// reported relative to the scan root.
//
// Python indexes relpath[0] in a loop and raises IndexError when fullpath
// equals basepath (common.py:121). Reachable when a scan target is a file
// rather than a directory, so the empty case is guarded here instead.
func RelPath(basepath, fullpath string) string {
	rel := fullpath
	if basepath != "" && strings.HasPrefix(fullpath, basepath) {
		rel = fullpath[len(basepath):]
	}
	return strings.TrimLeft(rel, "/")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./rake/ -v`
Expected: PASS, all four tests.

- [ ] **Step 5: Commit**

```bash
git add golang/rake/rake.go golang/rake/rake_test.go
git commit -m "feat(golang): add Rake base type and rake interfaces

Declares the Filterer, ContentRake and MetaRake interfaces. RelPath guards
the empty case where Python raises IndexError on fullpath == basepath."
```

---

### Task 7: `rake` package — `Pattern` (`RakePattern`)

This is the core of the port: group-number translation, rune offsets, and the self-dispatch that reproduces Python's `self.filter()` override chain.

**Files:**
- Create: `golang/rake/rakepattern.go`
- Test: `golang/rake/rakepattern_test.go`

**Interfaces:**
- Consumes: `Rake`, `Filterer`, `RelPath` (Task 6); `filter.RakeFilter`, `filter.FilterRegistry` (Tasks 3–4); `match.New` (Task 2); `walker.Context` (Task 5).
- Produces:
  - `type PatternOpts struct { Name, PType, PDesc, Severity, Pattern string; CtxGroup, KeyGroup, ValGroup *int; IgnoreCase bool; Timeout time.Duration }`
  - `func NewPattern(o PatternOpts) (*Pattern, error)`
  - `func (p *Pattern) AddFilter(f filter.RakeFilter)`
  - `func (p *Pattern) Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error)`
  - `func (p *Pattern) Filter(m *match.RakeMatch) bool`
  - `func (p *Pattern) SetSelf(f Filterer)` — subclasses call this to install their override
  - `func LoadPattern(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration) (*Pattern, error)`
  - `func cfgInt(cfg map[string]any, k string) *int`, `func cfgStr(cfg map[string]any, k string, def string) string`, `func cfgBoolean(cfg map[string]any, k string) bool` (exported to the package, used by Tasks 8–9)

- [ ] **Step 1: Write the failing test**

```go
package rake

import (
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

func ip(i int) *int { return &i }

func testCtx(line int) *walker.Context {
	return &walker.Context{
		BasePath: "/src", Path: "/src", Filename: "f.txt",
		FullPath: "/src/f.txt", FileType: "txt", HasFileType: true,
		LineNo: ip(line),
	}
}

func mustPattern(t *testing.T, pat string, ctx, key, val *int, ic bool) *Pattern {
	t.Helper()
	p, err := NewPattern(PatternOpts{
		Name: "RakePattern", PType: "test", PDesc: "desc", Severity: "LOW",
		Pattern: pat, CtxGroup: ctx, KeyGroup: key, ValGroup: val,
		IgnoreCase: ic, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewPattern(%q): %v", pat, err)
	}
	return p
}

func TestPatternRequiresContextGroup(t *testing.T) {
	_, err := NewPattern(PatternOpts{
		Name: "R", PType: "t", PDesc: "d", Severity: "LOW",
		Pattern: "(x)", CtxGroup: nil, Timeout: time.Second,
	})
	if err == nil {
		t.Error("a missing context group must be rejected")
	}
}

func TestPatternInvalidRegexErrors(t *testing.T) {
	_, err := NewPattern(PatternOpts{
		Name: "R", PType: "t", PDesc: "d", Severity: "LOW",
		Pattern: "([unclosed", CtxGroup: ip(0), Timeout: time.Second,
	})
	if err == nil {
		t.Error("an invalid pattern must return an error, not exit the process")
	}
}

func TestPatternExtractsGroupsWithPlusOneTranslation(t *testing.T) {
	// Config group k maps to regex group k+1.
	p := mustPattern(t, `((\w+)=(\w+))`, ip(0), ip(1), ip(2), false)
	got, err := p.Match(testCtx(3), "user=jeff\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	m := got[0]
	oc := match.NewOutputConfig(false, false, false)
	if v := m.Context(oc); v == nil || *v != "user=jeff" {
		t.Errorf("context: got %v", v)
	}
	if v := m.Key(); v == nil || *v != "user" {
		t.Errorf("key: got %v", v)
	}
	if v := m.Value(oc); v == nil || *v != "jeff" {
		t.Errorf("value: got %v", v)
	}
	if m.Line() == nil || *m.Line() != 3 {
		t.Errorf("line: got %v want 3", m.Line())
	}
	if m.File() != "f.txt" {
		t.Errorf("file must be relative to basepath: got %q", m.File())
	}
}

func TestPatternOffsetsAreRuneBased(t *testing.T) {
	p := mustPattern(t, `(secret(\d+))`, ip(0), nil, ip(1), false)
	got, err := p.Match(testCtx(1), "héllo 日本 secret42\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	// "héllo 日本 secret" is 15 runes; the digits start at rune 15.
	if off := got[0].ValueOffset(); off == nil || *off != 15 {
		t.Errorf("value offset must be in runes: got %v want 15", off)
	}
	if l := got[0].ValueLength(); l == nil || *l != 2 {
		t.Errorf("value length: got %v want 2", l)
	}
}

func TestPatternMultipleMatchesPerLine(t *testing.T) {
	p := mustPattern(t, `((\w+)=(\w+))`, ip(0), ip(1), ip(2), false)
	got, err := p.Match(testCtx(1), "a=1 b=2 c=3\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(got))
	}
}

func TestPatternNoMatchReturnsEmpty(t *testing.T) {
	p := mustPattern(t, `(zzz)`, ip(0), nil, nil, false)
	got, err := p.Match(testCtx(1), "nothing here\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected no matches, got %d", len(got))
	}
}

func TestPatternIgnorecase(t *testing.T) {
	p := mustPattern(t, `(PASSWORD)`, ip(0), nil, nil, true)
	got, _ := p.Match(testCtx(1), "password\n")
	if len(got) != 1 {
		t.Error("ignorecase must apply")
	}
}

// Python's m.groups(default='') yields "" for groups that did not participate.
func TestMatchGroupsPreservesEmptyForOptionalGroups(t *testing.T) {
	p := mustPattern(t, `((a)(b)?)`, ip(0), nil, nil, false)
	got, _ := p.Match(testCtx(1), "a\n")
	if len(got) != 1 {
		t.Fatal("expected 1 match")
	}
	g := got[0].MatchGroups
	if len(g) != 3 {
		t.Fatalf("expected 3 groups, got %d: %#v", len(g), g)
	}
	if g[0] != "a" || g[1] != "a" || g[2] != "" {
		t.Errorf("groups: got %#v want [a a \"\"]", g)
	}
}

// An unset optional group must stay distinguishable from an empty capture.
func TestUnparticipatingGroupLeavesFieldUnset(t *testing.T) {
	p := mustPattern(t, `((a)(b)?)`, ip(0), nil, ip(2), false)
	got, _ := p.Match(testCtx(1), "a\n")
	if len(got) != 1 {
		t.Fatal("expected 1 match")
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := got[0].Value(oc); v != nil {
		t.Errorf("a non-participating group must leave the value unset, got %q", *v)
	}
}

func TestPatternFilterDropsMatch(t *testing.T) {
	p := mustPattern(t, `((\w+)=(\w+))`, ip(0), ip(1), ip(2), false)
	f, err := filter.NewLiteralFilter(nil, strptr("jeff"), false)
	if err != nil {
		t.Fatal(err)
	}
	p.AddFilter(f)
	got, _ := p.Match(testCtx(1), "user=jeff\n")
	if len(got) != 0 {
		t.Errorf("a matching filter must drop the finding, got %d", len(got))
	}
}

func strptr(s string) *string { return &s }

// SetSelf reproduces Python's dispatch through self.filter().
func TestSelfDispatchIsUsedByMatch(t *testing.T) {
	p := mustPattern(t, `((\w+))`, ip(0), nil, ip(0), false)
	p.SetSelf(rejectAll{})
	got, _ := p.Match(testCtx(1), "anything\n")
	if len(got) != 0 {
		t.Error("Match must route filtering through the installed self")
	}
}

type rejectAll struct{}

func (rejectAll) Filter(*match.RakeMatch) bool { return false }

func TestLoadPatternFromConfig(t *testing.T) {
	cfg := map[string]any{
		"name": "auth token", "pattern": `((Basic|Bearer)\s+(\S{7,}))`,
		"description": "d", "severity": "HIGH",
		"contextgroup": 0, "valgroup": 2, "ignorecase": false,
	}
	p, err := LoadPattern(cfg, filter.NewFilterRegistry(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if p.PType() != "auth token" || p.Severity() != "HIGH" {
		t.Errorf("metadata: %#v", p)
	}
	got, _ := p.Match(testCtx(1), "Authorization: Bearer abcdefghij\n")
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := got[0].Value(oc); v == nil || *v != "abcdefghij" {
		t.Errorf("value: got %v", v)
	}
}

func TestLoadPatternMissingPatternErrors(t *testing.T) {
	_, err := LoadPattern(map[string]any{"name": "x", "contextgroup": 0},
		filter.NewFilterRegistry(), time.Second)
	if err == nil {
		t.Error("a missing pattern must error")
	}
}

func TestLoadPatternFiltersMustBeList(t *testing.T) {
	_, err := LoadPattern(map[string]any{
		"name": "x", "pattern": "(a)", "contextgroup": 0, "filters": "nope",
	}, filter.NewFilterRegistry(), time.Second)
	if err == nil {
		t.Error("a non-list filters key must error")
	}
}

func TestLoadPatternResolvesFilterSets(t *testing.T) {
	reg := filter.NewFilterRegistry()
	f, _ := filter.NewLiteralFilter(nil, strptr("hunter2"), false)
	if err := reg.RegisterSet("Test", []filter.RakeFilter{f}); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPattern(map[string]any{
		"name": "x", "pattern": `((\w+)=(\w+))`, "contextgroup": 0, "valgroup": 2,
		"filters": []any{map[string]any{"type": "set", "name": "Test"}},
	}, reg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := p.Match(testCtx(1), "pw=hunter2\n")
	if len(got) != 0 {
		t.Error("the expanded filter set must suppress the match")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./rake/ -v`
Expected: FAIL — `undefined: NewPattern`, `undefined: PatternOpts`, `undefined: LoadPattern`.

- [ ] **Step 3: Write the implementation**

```go
package rake

import (
	"fmt"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// PatternOpts configures a Pattern. CtxGroup is required; KeyGroup and
// ValGroup are optional. All three are config-level group numbers, which are
// 0-based indexes into a findall tuple and therefore one less than the regex
// group number.
type PatternOpts struct {
	Name     string
	PType    string
	PDesc    string
	Severity string
	Pattern  string

	CtxGroup *int
	KeyGroup *int
	ValGroup *int

	IgnoreCase bool
	Timeout    time.Duration
}

// Pattern is a regex applied to every line of content.
type Pattern struct {
	*Rake

	re       *regexp2.Regexp
	source   string
	ctxGroup *int
	keyGroup *int
	valGroup *int

	filters []filter.RakeFilter

	// self is the outermost Filterer, reproducing Python's dispatch through
	// self.filter(). Subclasses install themselves via SetSelf so that
	// Pattern.Match calls their override rather than this type's.
	self Filterer
}

func NewPattern(o PatternOpts) (*Pattern, error) {
	if o.CtxGroup == nil {
		return nil, fmt.Errorf("no context group given for Rake %q", o.PType)
	}

	name := o.Name
	if name == "" {
		name = "RakePattern"
	}
	base, err := NewRake(name, o.PType, o.PDesc, o.Severity, PartContent)
	if err != nil {
		return nil, err
	}

	opts := regexp2.None
	if o.IgnoreCase {
		opts = regexp2.IgnoreCase
	}
	re, err := regexp2.Compile(o.Pattern, opts)
	if err != nil {
		// Python prints and calls sys.exit(1) here (rakes.py:129). A library
		// returns the error and lets the caller decide.
		return nil, fmt.Errorf("failed to parse pattern %q: %w", o.Pattern, err)
	}
	re.MatchTimeout = o.Timeout

	p := &Pattern{
		Rake: base, re: re, source: o.Pattern,
		ctxGroup: o.CtxGroup, keyGroup: o.KeyGroup, valGroup: o.ValGroup,
	}
	p.self = p
	return p, nil
}

// SetSelf installs the outermost filter implementation. Subclass constructors
// must call this with themselves.
func (p *Pattern) SetSelf(f Filterer) { p.self = f }

func (p *Pattern) AddFilter(f filter.RakeFilter) { p.filters = append(p.filters, f) }

// Source returns the uncompiled pattern, for diagnostics.
func (p *Pattern) Source() string { return p.source }

// setFromGroup copies one regex group into the match via set, translating the
// config-level group number. A group that did not participate is skipped, so
// the field stays unset -- Python's None rather than "".
func setFromGroup(m *regexp2.Match, configGroup *int, set func(string, int, int)) {
	if configGroup == nil {
		return
	}
	g := m.GroupByNumber(*configGroup + 1) // findall-tuple index -> regex group
	if g == nil || len(g.Captures) == 0 {
		return
	}
	// regexp2 indexes in runes, which is what RakeMatch documents.
	set(g.String(), g.Index, g.Length)
}

// Match applies the pattern to one line and returns every surviving match.
func (p *Pattern) Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error) {
	var out []*match.RakeMatch
	relpath := "" // computed lazily, once per line, as Python does
	haveRel := false

	m, err := p.re.FindStringMatch(text)
	if err != nil {
		return nil, fmt.Errorf("rake %s: %w", p.Name(), err)
	}

	for m != nil {
		if !haveRel {
			relpath = RelPath(ctx.BasePath, ctx.FullPath)
			haveRel = true
		}

		rm := match.New(p, relpath, ctx.LineNo)
		setFromGroup(m, p.keyGroup, rm.SetKey)
		setFromGroup(m, p.valGroup, rm.SetValue)
		setFromGroup(m, p.ctxGroup, rm.SetContext)

		// Mirror m.groups(default=''): every group 1..N, "" when absent.
		groups := make([]string, 0, m.GroupCount()-1)
		for i := 1; i < m.GroupCount(); i++ {
			g := m.GroupByNumber(i)
			if g == nil || len(g.Captures) == 0 {
				groups = append(groups, "")
				continue
			}
			groups = append(groups, g.String())
		}
		rm.MatchGroups = groups

		if p.self.Filter(rm) {
			out = append(out, rm)
		}

		if m, err = p.re.FindNextMatch(m); err != nil {
			return nil, fmt.Errorf("rake %s: %w", p.Name(), err)
		}
	}

	return out, nil
}

// Filter applies the denylist. Filters suppress: if any matches, the finding
// is dropped, so this returns false.
func (p *Pattern) Filter(m *match.RakeMatch) bool {
	for _, f := range p.filters {
		if f.Match(m) {
			return false
		}
	}
	return true
}

// Config coercion helpers, shared with FileMeta and ContextPattern.

func cfgInt(cfg map[string]any, k string) *int {
	v, ok := cfg[k]
	if !ok || v == nil {
		return nil
	}
	switch n := v.(type) {
	case int:
		return &n
	case int64:
		i := int(n)
		return &i
	case float64:
		i := int(n)
		return &i
	default:
		return nil
	}
}

func cfgStr(cfg map[string]any, k, def string) string {
	v, ok := cfg[k]
	if !ok || v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func cfgStrPtr(cfg map[string]any, k string) *string {
	v, ok := cfg[k]
	if !ok || v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func cfgBoolean(cfg map[string]any, k string, def bool) bool {
	v, ok := cfg[k]
	if !ok || v == nil {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

// resolveFilters turns a rake's `filters:` config into filter instances,
// expanding FilterSet references through the registry.
func resolveFilters(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration, rakeName string) ([]filter.RakeFilter, error) {
	raw, present := cfg["filters"]
	if !present || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("filters must be a list for Rake %s", rakeName)
	}
	if reg != nil {
		return reg.LoadList(list, timeout)
	}
	out := make([]filter.RakeFilter, 0, len(list))
	for _, e := range list {
		fm, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("filter entries must be mappings for Rake %s", rakeName)
		}
		f, err := filter.Load(fm, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// LoadPattern builds a Pattern from a `type: SimplePattern` rake config.
func LoadPattern(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration) (*Pattern, error) {
	name := cfgStr(cfg, "name", "<-NotNamed->")
	pat := cfgStrPtr(cfg, "pattern")
	if pat == nil {
		return nil, fmt.Errorf("pattern must be given for rake %s", name)
	}

	p, err := NewPattern(PatternOpts{
		Name:     "RakePattern",
		PType:    name,
		PDesc:    cfgStr(cfg, "description", "<-NoDesc->"),
		Severity: cfgStr(cfg, "severity", "LOW"),
		Pattern:  *pat,
		CtxGroup: cfgInt(cfg, "contextgroup"),
		KeyGroup: cfgInt(cfg, "keygroup"),
		ValGroup: cfgInt(cfg, "valgroup"),

		IgnoreCase: cfgBoolean(cfg, "ignorecase", false),
		Timeout:    timeout,
	})
	if err != nil {
		return nil, err
	}

	filters, err := resolveFilters(cfg, reg, timeout, name)
	if err != nil {
		return nil, err
	}
	for _, f := range filters {
		p.AddFilter(f)
	}
	return p, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./rake/ -v`
Expected: PASS, all 15 tests.

- [ ] **Step 5: Commit**

```bash
git add golang/rake/rakepattern.go golang/rake/rakepattern_test.go
git commit -m "feat(golang): add RakePattern with group translation and self-dispatch

Translates config group k to regex group k+1, keeps rune-based offsets from
regexp2, and distinguishes a non-participating group from an empty capture.
SetSelf reproduces Python's dispatch through self.filter() so subclass
overrides run; Go embedding alone would always call the base method.

An invalid pattern returns an error rather than calling sys.exit(1)."
```

---

### Task 8: `rake` package — `FileMeta`

**Files:**
- Create: `golang/rake/rakefilemeta.go`
- Test: `golang/rake/rakefilemeta_test.go`

**Interfaces:**
- Consumes: `Rake`, `RelPath` (Task 6); `cfgStr`, `cfgStrPtr`, `cfgBoolean` (Task 7); `match.New`; `walker.Context`.
- Produces:
  - `type FileMetaOpts struct { PType, PDesc, Severity string; Path, File, Ext *string; All, IgnoreCase bool; Timeout time.Duration }`
  - `func NewFileMeta(o FileMetaOpts) (*FileMeta, error)`
  - `func (f *FileMeta) MatchContext(ctx *walker.Context) (*match.RakeMatch, error)`
  - `func LoadFileMeta(cfg map[string]any, timeout time.Duration) (*FileMeta, error)`

- [ ] **Step 1: Write the failing test**

```go
package rake

import (
	"testing"
	"time"
)

func ctxFor(base, dir, name, ext string, hasExt bool) *walkerCtx {
	return newWalkerCtx(base, dir, name, ext, hasExt)
}

func mustFileMeta(t *testing.T, path, file, ext *string, all, ic bool) *FileMeta {
	t.Helper()
	f, err := NewFileMeta(FileMetaOpts{
		PType: "ssh identity file", PDesc: "d", Severity: "HIGH",
		Path: path, File: file, Ext: ext, All: all, IgnoreCase: ic,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFileMetaPartIsFileMeta(t *testing.T) {
	f := mustFileMeta(t, nil, strptr("^id_rsa$"), nil, true, false)
	if f.Part() != PartFileMeta {
		t.Errorf("part: got %q want %q", f.Part(), PartFileMeta)
	}
}

func TestFileMetaMatchesByFilePattern(t *testing.T) {
	f := mustFileMeta(t, nil, strptr("^id_(rsa1?|dsa|ecdsa|ed25519)$"), nil, false, false)
	m, err := f.MatchContext(newWalkerCtx("/src", "/src/.ssh", "id_rsa", "", false))
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected a match for id_rsa")
	}
	m2, _ := f.MatchContext(newWalkerCtx("/src", "/src", "notes.txt", "txt", true))
	if m2 != nil {
		t.Error("expected no match for notes.txt")
	}
}

func TestFileMetaMatchesByExtension(t *testing.T) {
	f := mustFileMeta(t, nil, nil, strptr("^(pem|pfx|p12|p7b|key)$"), false, true)
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "server.PEM", "PEM", true))
	if m == nil {
		t.Error("ignorecase extension match expected")
	}
}

// A file with no extension cannot satisfy an extension pattern; that counts as
// "not matched" rather than "not defined" (rakes.py:56-64).
func TestFileMetaExtensionPatternFailsWhenNoExtension(t *testing.T) {
	f := mustFileMeta(t, nil, nil, strptr("^pem$"), true, false)
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "noext", "", false))
	if m != nil {
		t.Error("a file with no extension must not satisfy an extension pattern")
	}
}

func TestFileMetaAllRequiredSemantics(t *testing.T) {
	// all=true: every defined pattern must match.
	both := mustFileMeta(t, nil, strptr("^keystore$"), strptr("^jks$"), true, false)
	if m, _ := both.MatchContext(newWalkerCtx("/src", "/src", "keystore", "", false)); m != nil {
		t.Error("all=true must require the extension pattern to match too")
	}
	if m, _ := both.MatchContext(newWalkerCtx("/src", "/src", "keystore.jks", "jks", true)); m == nil {
		t.Error("all=true must match when both patterns match")
	}

	// all=false: any defined pattern matching is enough.
	any := mustFileMeta(t, nil, strptr("^keystore$"), strptr("^jks$"), false, false)
	if m, _ := any.MatchContext(newWalkerCtx("/src", "/src", "keystore", "", false)); m == nil {
		t.Error("all=false must match on the file pattern alone")
	}
	if m, _ := any.MatchContext(newWalkerCtx("/src", "/src", "other.jks", "jks", true)); m == nil {
		t.Error("all=false must match on the extension alone")
	}
}

func TestFileMetaNoPatternsReturnsNil(t *testing.T) {
	f, err := NewFileMeta(FileMetaOpts{
		PType: "t", PDesc: "d", Severity: "LOW", All: true, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "anything", "", false))
	if m != nil {
		t.Error("with no patterns defined the result must be nil")
	}
}

func TestFileMetaReportsRelativePathAndNoLine(t *testing.T) {
	f := mustFileMeta(t, nil, strptr("^id_rsa$"), nil, false, false)
	m, _ := f.MatchContext(newWalkerCtx("/src", "/src/keys", "id_rsa", "", false))
	if m == nil {
		t.Fatal("expected a match")
	}
	if m.File() != "keys/id_rsa" {
		t.Errorf("file must be relative to basepath: got %q", m.File())
	}
	if m.Line() != nil {
		t.Errorf("a filemeta match carries no line number, got %v", m.Line())
	}
}

func TestFileMetaPathPattern(t *testing.T) {
	f := mustFileMeta(t, strptr(`.*/\.ssh$`), nil, nil, true, false)
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src/.ssh", "config", "", false)); m == nil {
		t.Error("expected the path pattern to match")
	}
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src/etc", "config", "", false)); m != nil {
		t.Error("expected no match outside .ssh")
	}
}

func TestLoadFileMetaRequiresNameDescSeverity(t *testing.T) {
	for _, cfg := range []map[string]any{
		{"description": "d", "severity": "HIGH", "file": "^x$"},
		{"name": "n", "severity": "HIGH", "file": "^x$"},
		{"name": "n", "description": "d", "file": "^x$"},
	} {
		if _, err := LoadFileMeta(cfg, time.Second); err == nil {
			t.Errorf("missing required element must error: %v", cfg)
		}
	}
}

func TestLoadFileMetaRequiresAtLeastOnePattern(t *testing.T) {
	_, err := LoadFileMeta(map[string]any{
		"name": "n", "description": "d", "severity": "HIGH",
		"path": nil, "file": nil, "extension": nil,
	}, time.Second)
	if err == nil {
		t.Error("at least one of path, file, extension must be required")
	}
}

func TestLoadFileMetaBuildsRake(t *testing.T) {
	f, err := LoadFileMeta(map[string]any{
		"name": "netrc file", "description": "d", "severity": "HIGH",
		"file": `\.?netrc$`, "extension": "netrc",
		"all": false, "ignorecase": true,
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if f.PType() != "netrc file" {
		t.Errorf("ptype: %q", f.PType())
	}
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src", ".netrc", "netrc", true)); m == nil {
		t.Error("expected .netrc to match")
	}
}

// `all` defaults to true when the key is absent.
func TestLoadFileMetaAllDefaultsTrue(t *testing.T) {
	f, err := LoadFileMeta(map[string]any{
		"name": "n", "description": "d", "severity": "LOW",
		"file": "^keystore$", "extension": "^jks$",
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := f.MatchContext(newWalkerCtx("/src", "/src", "keystore", "", false)); m != nil {
		t.Error("all must default to true, requiring both patterns")
	}
}
```

Add this shared helper to `golang/rake/rake_test.go`:

```go
func newWalkerCtx(base, dir, name, ext string, hasExt bool) *walker.Context {
	return &walker.Context{
		BasePath: base, Path: dir, Filename: name,
		FullPath: dir + "/" + name, FileType: ext, HasFileType: hasExt,
	}
}

type walkerCtx = walker.Context
```

and add `"github.com/jcwoods/datarake/golang/walker"` to that file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./rake/ -run FileMeta -v`
Expected: FAIL — `undefined: NewFileMeta`, `undefined: FileMetaOpts`.

- [ ] **Step 3: Write the implementation**

```go
package rake

import (
	"fmt"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// FileMetaOpts configures a FileMeta rake. At least one of Path, File or Ext
// must be set. All selects between "every defined pattern must match" and
// "any defined pattern matching is enough".
type FileMetaOpts struct {
	PType    string
	PDesc    string
	Severity string

	Path *string // applied to the directory name
	File *string // applied to the basename
	Ext  *string // applied to the extension

	All        bool
	IgnoreCase bool
	Timeout    time.Duration
}

// FileMeta matches on file metadata rather than content, so it runs once per
// file and returns a single match or nil.
type FileMeta struct {
	*Rake

	pathRe *regexp2.Regexp
	fileRe *regexp2.Regexp
	extRe  *regexp2.Regexp

	allRequired bool
}

func NewFileMeta(o FileMetaOpts) (*FileMeta, error) {
	base, err := NewRake("RakeFileMeta", o.PType, o.PDesc, o.Severity, PartFileMeta)
	if err != nil {
		return nil, err
	}

	opts := regexp2.None
	if o.IgnoreCase {
		opts = regexp2.IgnoreCase
	}
	// Python uses re.match here, anchored at position 0 only.
	compile := func(p *string) (*regexp2.Regexp, error) {
		if p == nil {
			return nil, nil
		}
		re, err := regexp2.Compile(`\A(?:`+*p+`)`, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pattern %q: %w", *p, err)
		}
		re.MatchTimeout = o.Timeout
		return re, nil
	}

	f := &FileMeta{Rake: base, allRequired: o.All}
	if f.pathRe, err = compile(o.Path); err != nil {
		return nil, err
	}
	if f.fileRe, err = compile(o.File); err != nil {
		return nil, err
	}
	if f.extRe, err = compile(o.Ext); err != nil {
		return nil, err
	}
	return f, nil
}

// MatchContext evaluates the defined patterns against the context.
func (f *FileMeta) MatchContext(ctx *walker.Context) (*match.RakeMatch, error) {
	// Report a relative path so filemeta findings look like content findings.
	relfile := ctx.FullPath
	if ctx.BasePath != "" {
		relfile = RelPath(ctx.BasePath, ctx.FullPath)
	}

	// A field that is absent counts as "not matched" rather than "not
	// defined": a file with no extension cannot satisfy an extension pattern.
	var checks []bool
	test := func(re *regexp2.Regexp, subject string, present bool) error {
		if re == nil {
			return nil
		}
		if !present {
			checks = append(checks, false)
			return nil
		}
		ok, err := re.MatchString(subject)
		if err != nil {
			return fmt.Errorf("rake %s: %w", f.Name(), err)
		}
		checks = append(checks, ok)
		return nil
	}

	if err := test(f.pathRe, ctx.Path, ctx.Path != ""); err != nil {
		return nil, err
	}
	if err := test(f.fileRe, ctx.Filename, ctx.Filename != ""); err != nil {
		return nil, err
	}
	if err := test(f.extRe, ctx.FileType, ctx.HasFileType); err != nil {
		return nil, err
	}

	if len(checks) == 0 {
		return nil, nil
	}

	matched := true
	if f.allRequired {
		for _, c := range checks {
			if !c {
				matched = false
				break
			}
		}
	} else {
		matched = false
		for _, c := range checks {
			if c {
				matched = true
				break
			}
		}
	}
	if !matched {
		return nil, nil
	}

	// line is nil: a filemeta finding has no line number.
	rm := match.New(f, relfile, nil)
	if !f.Filter(rm) {
		return nil, nil
	}
	return rm, nil
}

// LoadFileMeta builds a FileMeta from a `type: FileMeta` rake config.
func LoadFileMeta(cfg map[string]any, timeout time.Duration) (*FileMeta, error) {
	name := cfgStrPtr(cfg, "name")
	desc := cfgStrPtr(cfg, "description")
	sev := cfgStrPtr(cfg, "severity")

	if name == nil || desc == nil || sev == nil {
		n := "<unnamed>"
		if name != nil {
			n = *name
		}
		return nil, fmt.Errorf("missing required configuration element(s) for rake: %s", n)
	}

	path := cfgStrPtr(cfg, "path")
	file := cfgStrPtr(cfg, "file")
	ext := cfgStrPtr(cfg, "extension")

	if path == nil && file == nil && ext == nil {
		return nil, fmt.Errorf("at least one of path, file, and extension must be set for rake: %s", *name)
	}

	return NewFileMeta(FileMetaOpts{
		PType: *name, PDesc: *desc, Severity: *sev,
		Path: path, File: file, Ext: ext,
		All:        cfgBoolean(cfg, "all", true),
		IgnoreCase: cfgBoolean(cfg, "ignorecase", false),
		Timeout:    timeout,
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./rake/ -v`
Expected: PASS, all tests from Tasks 6–8.

- [ ] **Step 5: Commit**

```bash
git add golang/rake/rakefilemeta.go golang/rake/rakefilemeta_test.go golang/rake/rake_test.go
git commit -m "feat(golang): add RakeFileMeta

Matches on path, basename and extension with all/any semantics. An absent
field counts as not-matched rather than not-defined, so a file with no
extension cannot satisfy an extension pattern. Patterns are anchored with
\\A to reproduce re.match."
```

---

### Task 9: `rake` package — `ContextPattern`

**Files:**
- Create: `golang/rake/rakecontextpattern.go`
- Test: `golang/rake/rakecontextpattern_test.go`

**Interfaces:**
- Consumes: `Rake`, `Pattern`, `NewPattern`, `resolveFilters`, config helpers (Tasks 6–7).
- Produces:
  - `func NewContextPattern(ptype, pdesc, severity string) (*ContextPattern, error)`
  - `func (c *ContextPattern) AddContext(fileType *string, p *Pattern) error` — a nil `fileType` registers the default
  - `func (c *ContextPattern) Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error)`
  - `func (c *ContextPattern) Filter(m *match.RakeMatch) bool`
  - `func LoadContextPattern(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration) (*ContextPattern, error)`

**Note.** `skipcontexts:` on the `token` rake is read by no Python code
(`RakeContextPattern.load` reads only `name`, `description`, `severity`,
`contexts`). It stays inert here for the same reason as `Global.IgnorePasswords`:
wiring it would invent behavior that has never existed.

- [ ] **Step 1: Write the failing test**

```go
package rake

import (
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

func ctxWithType(ext string, hasExt bool, line int) *walker.Context {
	c := newWalkerCtx("/src", "/src", "f", ext, hasExt)
	c.LineNo = ip(line)
	return c
}

func TestContextPatternRoutesByExtension(t *testing.T) {
	cp, err := NewContextPattern("token", "d", "MEDIUM")
	if err != nil {
		t.Fatal(err)
	}
	pyPat := mustPattern(t, `(py_(\w+))`, ip(0), nil, ip(1), false)
	jsPat := mustPattern(t, `(js_(\w+))`, ip(0), nil, ip(1), false)
	if err := cp.AddContext(strptr("py"), pyPat); err != nil {
		t.Fatal(err)
	}
	if err := cp.AddContext(strptr("js"), jsPat); err != nil {
		t.Fatal(err)
	}

	oc := match.NewOutputConfig(false, false, false)

	got, _ := cp.Match(ctxWithType("py", true, 1), "py_secret js_secret\n")
	if len(got) != 1 {
		t.Fatalf("py context: expected 1 match, got %d", len(got))
	}
	if v := got[0].Value(oc); v == nil || *v != "secret" {
		t.Errorf("py context matched the wrong pattern: %v", v)
	}

	got2, _ := cp.Match(ctxWithType("js", true, 1), "py_secret js_secret\n")
	if len(got2) != 1 {
		t.Fatalf("js context: expected 1 match, got %d", len(got2))
	}
}

func TestContextPatternFallsBackToDefault(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	def := mustPattern(t, `(any_(\w+))`, ip(0), nil, ip(1), false)
	if err := cp.AddContext(nil, def); err != nil {
		t.Fatal(err)
	}
	got, _ := cp.Match(ctxWithType("rb", true, 1), "any_thing\n")
	if len(got) != 1 {
		t.Error("an unmatched extension must fall back to the default context")
	}
	// A file with no extension also uses the default.
	got2, _ := cp.Match(ctxWithType("", false, 1), "any_thing\n")
	if len(got2) != 1 {
		t.Error("a file with no extension must use the default context")
	}
}

func TestContextPatternNoDefaultReturnsNothing(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	p := mustPattern(t, `(py_(\w+))`, ip(0), nil, ip(1), false)
	cp.AddContext(strptr("py"), p)
	got, err := cp.Match(ctxWithType("rb", true, 1), "py_secret\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("without a default context an unknown extension must yield nothing, got %d", len(got))
	}
}

func TestContextPatternDuplicateContextErrors(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	p := mustPattern(t, `(a)`, ip(0), nil, nil, false)
	if err := cp.AddContext(strptr("py"), p); err != nil {
		t.Fatal(err)
	}
	if err := cp.AddContext(strptr("py"), p); err == nil {
		t.Error("a duplicate file type must error")
	}
	if err := cp.AddContext(nil, p); err != nil {
		t.Fatal(err)
	}
	if err := cp.AddContext(nil, p); err == nil {
		t.Error("a duplicate default context must error")
	}
}

func TestContextPatternPartIsContent(t *testing.T) {
	cp, _ := NewContextPattern("token", "d", "MEDIUM")
	if cp.Part() != PartContent {
		t.Errorf("part: got %q want %q", cp.Part(), PartContent)
	}
}

func TestLoadContextPatternFromConfig(t *testing.T) {
	cfg := map[string]any{
		"name": "token", "description": "possible token", "severity": "MEDIUM",
		"contexts": []any{
			map[string]any{
				"context": nil,
				"pattern": `((\w+)=(\w+))`,
				"contextgroup": 0, "keygroup": 1, "valgroup": 2,
				"ignorecase": true,
			},
			map[string]any{
				"context": []any{"c", "java"},
				"pattern": `((\w+) := (\w+))`,
				"contextgroup": 0, "keygroup": 1, "valgroup": 2,
			},
		},
	}
	cp, err := LoadContextPattern(cfg, filter.NewFilterRegistry(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cp.PType() != "token" || cp.Severity() != "MEDIUM" {
		t.Errorf("metadata: %#v", cp)
	}

	oc := match.NewOutputConfig(false, false, false)
	got, _ := cp.Match(ctxWithType("txt", true, 1), "tok=abc\n")
	if len(got) != 1 {
		t.Fatalf("default context: expected 1, got %d", len(got))
	}
	if v := got[0].Value(oc); v == nil || *v != "abc" {
		t.Errorf("value: %v", v)
	}

	// A scalar `context:` must work as well as a list.
	got2, _ := cp.Match(ctxWithType("java", true, 1), "tok := abc\n")
	if len(got2) != 1 {
		t.Fatalf("java context: expected 1, got %d", len(got2))
	}
}

func TestLoadContextPatternMissingPatternErrors(t *testing.T) {
	_, err := LoadContextPattern(map[string]any{
		"name": "token", "description": "d", "severity": "LOW",
		"contexts": []any{map[string]any{"context": nil, "contextgroup": 0}},
	}, filter.NewFilterRegistry(), time.Second)
	if err == nil {
		t.Error("a context without a pattern must error")
	}
}

func TestLoadContextPatternSharesOnePatternAcrossFileTypes(t *testing.T) {
	cfg := map[string]any{
		"name": "token", "description": "d", "severity": "LOW",
		"contexts": []any{
			map[string]any{
				"context": []any{"c", "h", "cpp"},
				"pattern": `((\w+)=(\w+))`,
				"contextgroup": 0, "valgroup": 2,
			},
		},
	}
	cp, err := LoadContextPattern(cfg, filter.NewFilterRegistry(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{"c", "h", "cpp"} {
		got, _ := cp.Match(ctxWithType(ext, true, 1), "a=b\n")
		if len(got) != 1 {
			t.Errorf("extension %q: expected 1 match, got %d", ext, len(got))
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./rake/ -run ContextPattern -v`
Expected: FAIL — `undefined: NewContextPattern`.

- [ ] **Step 3: Write the implementation**

```go
package rake

import (
	"fmt"
	"time"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/walker"
)

// ContextPattern binds patterns to file extensions. Each context is a Pattern;
// the rake selects one by the scanned file's extension, falling back to a
// default context when present.
type ContextPattern struct {
	*Rake

	byType     map[string]*Pattern
	def        *Pattern
	hasDefault bool
}

func NewContextPattern(ptype, pdesc, severity string) (*ContextPattern, error) {
	base, err := NewRake("RakeContextPattern", ptype, pdesc, severity, PartContent)
	if err != nil {
		return nil, err
	}
	return &ContextPattern{Rake: base, byType: map[string]*Pattern{}}, nil
}

// AddContext registers a Pattern for one file type. A nil fileType registers
// the default context, which Python keys as None.
func (c *ContextPattern) AddContext(fileType *string, p *Pattern) error {
	if fileType == nil {
		if c.hasDefault {
			return fmt.Errorf("multiple definitions for file type None in rake %s", c.Name())
		}
		c.def, c.hasDefault = p, true
		return nil
	}
	if _, dup := c.byType[*fileType]; dup {
		return fmt.Errorf("multiple definitions for file type %s in rake %s", *fileType, c.Name())
	}
	c.byType[*fileType] = p
	return nil
}

// Match selects the pattern for this file's extension and delegates to it.
func (c *ContextPattern) Match(ctx *walker.Context, text string) ([]*match.RakeMatch, error) {
	var p *Pattern
	if ctx.HasFileType {
		p = c.byType[ctx.FileType]
	}
	if p == nil && c.hasDefault {
		p = c.def
	}
	if p == nil {
		return nil, nil
	}
	return p.Match(ctx, text)
}

// Filter is a no-op at this level: each context Pattern owns its own filters
// and applies them during Match.
func (c *ContextPattern) Filter(m *match.RakeMatch) bool { return true }

// LoadContextPattern builds a ContextPattern from a `type: ContextPattern`
// rake config.
//
// Note: the `skipcontexts:` key that appears on the token rake is read by no
// code, here or in Python. It is left inert deliberately -- honoring it would
// add suppression behavior that has never existed.
func LoadContextPattern(cfg map[string]any, reg *filter.FilterRegistry, timeout time.Duration) (*ContextPattern, error) {
	name := cfgStr(cfg, "name", "<-None->")
	desc := cfgStr(cfg, "description", "<-None->")
	sev := cfgStr(cfg, "severity", "LOW")

	cp, err := NewContextPattern(name, desc, sev)
	if err != nil {
		return nil, err
	}

	rawContexts, ok := cfg["contexts"].([]any)
	if !ok {
		return cp, nil
	}

	for _, rc := range rawContexts {
		cm, ok := rc.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("contexts entries must be mappings for rake %s", name)
		}

		pat := cfgStrPtr(cm, "pattern")
		if pat == nil {
			return nil, fmt.Errorf("pattern must be given for rake %s context", name)
		}

		p, err := NewPattern(PatternOpts{
			Name:     "RakePattern",
			PType:    name,
			PDesc:    desc,
			Severity: sev,
			Pattern:  *pat,
			CtxGroup: cfgInt(cm, "contextgroup"),
			KeyGroup: cfgInt(cm, "keygroup"),
			ValGroup: cfgInt(cm, "valgroup"),

			IgnoreCase: cfgBoolean(cm, "ignorecase", false),
			Timeout:    timeout,
		})
		if err != nil {
			return nil, err
		}

		filters, err := resolveFilters(cm, reg, timeout, name)
		if err != nil {
			return nil, err
		}
		for _, f := range filters {
			p.AddFilter(f)
		}

		// `context:` may be a scalar, a list, or null (the default context).
		// One Pattern instance is shared across every listed file type.
		for _, ft := range contextFileTypes(cm["context"]) {
			if err := cp.AddContext(ft, p); err != nil {
				return nil, err
			}
		}
	}

	return cp, nil
}

// contextFileTypes normalizes the `context:` value to a list of file types,
// where a nil entry means the default context.
func contextFileTypes(v any) []*string {
	switch t := v.(type) {
	case nil:
		return []*string{nil}
	case string:
		s := t
		return []*string{&s}
	case []any:
		out := make([]*string, 0, len(t))
		for _, e := range t {
			if e == nil {
				out = append(out, nil)
				continue
			}
			if s, ok := e.(string); ok {
				v := s
				out = append(out, &v)
			}
		}
		return out
	default:
		return nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./rake/ -v`
Expected: PASS, all tests from Tasks 6–9.

- [ ] **Step 5: Commit**

```bash
git add golang/rake/rakecontextpattern.go golang/rake/rakecontextpattern_test.go
git commit -m "feat(golang): add RakeContextPattern

Routes by file extension with an optional default context. A scalar, list
or null 'context:' value are all accepted, and one Pattern instance is
shared across the file types that list it.

The token rake's skipcontexts: key stays inert, as in Python."
```

---

### Task 10: `rake` package — `Hostname` and `Email`

These are library-only rakes: `loadConfig` can build only `ContextPattern`,
`FileMeta` and `SimplePattern` (`__main__.py:363-365`), so nothing in the scan
path constructs them. They are exported API exercised by the test suite, and
they are the only consumers of the TLD list, which is why `Global.CommonTLDs`
affects tests and library callers but not CLI scans.

**Files:**
- Create: `golang/rake/rakehostname.go`, `golang/rake/rakeemail.go`
- Test: `golang/rake/rakehostname_test.go`, `golang/rake/rakeemail_test.go`

**Interfaces:**
- Consumes: `Pattern`, `NewPattern`, `PatternOpts`, `SetSelf` (Task 7).
- Produces:
  - `var DefaultTLDs = []string{...}` (19 entries, from `RakeHostname.TLDs`)
  - `func IsValidHostname(fqdn string, minparts int, tlds []string) bool`
  - `func NewHostname(domain *string, tlds []string, timeout time.Duration) (*Hostname, error)`
  - `func (h *Hostname) Filter(m *match.RakeMatch) bool`
  - `func NewEmail(domain *string, tlds []string, timeout time.Duration) (*Email, error)`
  - `func (e *Email) Filter(m *match.RakeMatch) bool`

- [ ] **Step 1: Write the failing tests**

```go
package rake

import (
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
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	cases := []struct {
		fqdn     string
		minparts int
		want     bool
	}{
		{"srv.example.com", 3, true},
		{"a", 3, false},                    // too short
		{"example.com", 3, false},          // too few parts
		{"example.com", 2, true},           // minparts override
		{"srv.example.zzz", 3, false},      // bad TLD
		{"srv.example.COM", 3, true},       // TLD compared case-insensitively
		{long + ".example.com", 3, false},  // label > 63
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd golang && go test ./rake/ -run 'Hostname|Email' -v`
Expected: FAIL — `undefined: NewHostname`, `undefined: DefaultTLDs`.

- [ ] **Step 3: Write `rakehostname.go`**

```go
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
	v := m.Value(plainOutputConfig())
	if v == nil {
		return false
	}
	if !IsValidHostname(*v, 3, h.tlds) {
		return false
	}
	return h.Pattern.Filter(m)
}
```

Add this helper to `golang/rake/rake.go`:

```go
// plainOutputConfig is a non-secure view used when a rake's own Filter needs
// to inspect the matched text. Filtering runs before output is configured, and
// a filter must see the real value to judge it.
var plainOutputConfig = func() func() *match.OutputConfig {
	var oc *match.OutputConfig
	return func() *match.OutputConfig {
		if oc == nil {
			oc = match.NewOutputConfig(false, false, false)
		}
		return oc
	}
}()
```

- [ ] **Step 4: Write `rakeemail.go`**

```go
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
	v := m.Value(plainOutputConfig())
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd golang && go test ./rake/ -v`
Expected: PASS, all tests from Tasks 6–10.

- [ ] **Step 6: Commit**

```bash
git add golang/rake/rakehostname.go golang/rake/rakeemail.go \
        golang/rake/rakehostname_test.go golang/rake/rakeemail_test.go golang/rake/rake.go
git commit -m "feat(golang): add RakeHostname and RakeEmail

Both install themselves via SetSelf so Pattern.Match routes filtering
through their override and then chains to the base denylist, reproducing
super().filter(m). The TLD list is injectable, since Global.CommonTLDs
overrides it for library callers."
```

---

### Task 11: `rake` package — `BasicAuth` and `JWTAuth`

**Files:**
- Create: `golang/rake/rakebasicauth.go`, `golang/rake/rakejwtauth.go`
- Test: `golang/rake/rakebasicauth_test.go`, `golang/rake/rakejwtauth_test.go`

**Interfaces:**
- Consumes: `Pattern`, `NewPattern`, `SetSelf`, `plainOutputConfig` (Tasks 7, 10).
- Produces:
  - `func NewBasicAuth(minlen int, timeout time.Duration) (*BasicAuth, error)`
  - `func NewJWTAuth(timeout time.Duration) (*JWTAuth, error)`
  - `Filter` on both

- [ ] **Step 1: Write the failing tests**

```go
package rake

import (
	"encoding/base64"
	"testing"
	"time"
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
	oc := plainOutputConfig()
	if v := got[0].Context(oc); v == nil || *v != "Basic "+tok {
		t.Errorf("context must be the whole token: got %v", v)
	}
	if v := got[0].Value(oc); v == nil || *v != tok {
		t.Errorf("value must be the base64 payload: got %v", v)
	}
}

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd golang && go test ./rake/ -run 'BasicAuth|JWT' -v`
Expected: FAIL — `undefined: NewBasicAuth`, `undefined: NewJWTAuth`.

- [ ] **Step 3: Write `rakebasicauth.go`**

```go
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
```

- [ ] **Step 4: Write `rakejwtauth.go`**

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd golang && go test ./rake/ -v`
Expected: PASS, all tests from Tasks 6–11.

- [ ] **Step 6: Commit**

```bash
git add golang/rake/rakebasicauth.go golang/rake/rakejwtauth.go \
        golang/rake/rakebasicauth_test.go golang/rake/rakejwtauth_test.go
git commit -m "feat(golang): add RakeBasicAuth and RakeJWTAuth

Both validate their candidates after matching: BasicAuth decodes and
requires printable text with a colon at index >= 1; JWTAuth requires the
header and payload to decode and parse as JSON.

JWTAuth reproduces the padding arithmetic from rakes.py:515 verbatim,
including that a section of length %4 == 3 gets three '=' rather than one
and is therefore filtered."
```

---

### Task 12: `rakeset` package — `RakeSet`, encoding detection, universal newlines

**Files:**
- Create: `golang/rakeset/rakeset.go`
- Test: `golang/rakeset/rakeset_test.go`

**Interfaces:**
- Consumes: `rake.ContentRake`, `rake.MetaRake`, `rake.PartContent`, `rake.PartFileMeta` (Task 6); `match.RakeMatch`; `walker.Context`.
- Produces:
  - `type Stats struct { Files, Lines, Hits, Bytes int64 }`
  - `func (s *Stats) Add(o Stats)`
  - `var DefaultExcludeExtensions = []string{...}` (from `RakeSet.DEFAULT_BLACKLIST`, dotted)
  - `func New(verbose bool, excludeExtensions []string) *RakeSet`
  - `func (rs *RakeSet) Add(r any) error`
  - `func (rs *RakeSet) MatchContext(ctx *walker.Context) ([]*match.RakeMatch, error)`
  - `func (rs *RakeSet) MatchContent(ctx *walker.Context, text string) ([]*match.RakeMatch, error)`
  - `func (rs *RakeSet) Scan(ctx *walker.Context) ([]*match.RakeMatch, Stats, error)`
  - `func NormalizeExtension(e string) string`

**Concurrency contract.** `Scan` mutates no `RakeSet` state and writes no
output, so it is safe to call from many goroutines at once. Each `Context` is
created by the walker and owned solely by its scanning goroutine, so mutating
`ctx.LineNo` and `ctx.Encoding` needs no lock.

- [ ] **Step 1: Write the failing test**

```go
package rakeset

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/walker"
)

func ip(i int) *int       { return &i }
func sp(s string) *string { return &s }

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ctxFor(base, full string) *walker.Context {
	dir, name := filepath.Split(full)
	dir = filepath.Clean(dir)
	ext, has := "", false
	if i := len(name) - 1; i >= 0 {
		for j := len(name) - 1; j >= 0; j-- {
			if name[j] == '.' {
				ext, has = name[j+1:], true
				break
			}
		}
	}
	return &walker.Context{
		BasePath: base, Path: dir, Filename: name, FullPath: full,
		FileType: ext, HasFileType: has,
	}
}

func pwPattern(t *testing.T) *rake.Pattern {
	t.Helper()
	p, err := rake.NewPattern(rake.PatternOpts{
		Name: "RakePattern", PType: "password", PDesc: "d", Severity: "HIGH",
		Pattern: `((\w+)=(\w+))`, CtxGroup: ip(0), KeyGroup: ip(1), ValGroup: ip(2),
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAddDispatchesByPart(t *testing.T) {
	rs := New(false, nil)
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	fm, err := rake.NewFileMeta(rake.FileMetaOpts{
		PType: "ssh", PDesc: "d", Severity: "HIGH",
		File: sp("^id_rsa$"), All: true, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Add(fm); err != nil {
		t.Fatal(err)
	}
	if got := rs.ContentCount(); got != 1 {
		t.Errorf("content rakes: got %d want 1", got)
	}
	if got := rs.MetaCount(); got != 1 {
		t.Errorf("meta rakes: got %d want 1", got)
	}
	if err := rs.Add("not a rake"); err == nil {
		t.Error("an unknown rake type must error")
	}
}

func TestScanCountsLinesWithoutOffByOne(t *testing.T) {
	dir := t.TempDir()
	// Three lines of content.
	p := writeFile(t, dir, "a.txt", "one\ntwo\nthree\n")
	rs := New(false, nil)
	_, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Lines != 3 {
		t.Errorf("lines: got %d want 3 (Python reports 4)", stats.Lines)
	}
	if stats.Files != 1 {
		t.Errorf("files: got %d want 1", stats.Files)
	}
	if stats.Bytes != 14 {
		t.Errorf("bytes: got %d want 14", stats.Bytes)
	}
}

func TestScanFindsContentMatches(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "a.properties", "user=jeff\npassword=hunter2\n")
	rs := New(false, nil)
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(found))
	}
	if stats.Hits != 2 {
		t.Errorf("hits: got %d want 2", stats.Hits)
	}
	oc := match.NewOutputConfig(false, false, false)
	if v := found[1].Value(oc); v == nil || *v != "hunter2" {
		t.Errorf("second finding value: got %v", v)
	}
	if found[1].Line() == nil || *found[1].Line() != 2 {
		t.Errorf("second finding line: got %v want 2", found[1].Line())
	}
}

func TestScanSkipsBlacklistedExtensions(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "logo.PNG", "password=hunter2\n")
	rs := New(false, nil) // nil => DefaultExcludeExtensions
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 || stats.Files != 0 {
		t.Errorf("a blacklisted extension must be skipped entirely: %d findings, %d files", len(found), stats.Files)
	}
}

func TestScanHonorsConfiguredExtensionList(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "notes.md", "password=hunter2\n")
	// Config-style entries carry no leading dot.
	rs := New(false, []string{"md"})
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, _, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("a configured extension must be excluded, got %d findings", len(found))
	}
	// A .png is no longer excluded once the config replaces the defaults.
	p2 := writeFile(t, dir, "x.png", "password=hunter2\n")
	found2, _, err := rs.Scan(ctxFor(dir, p2))
	if err != nil {
		t.Fatal(err)
	}
	if len(found2) != 1 {
		t.Errorf("the configured list replaces the defaults, got %d findings", len(found2))
	}
}

func TestNormalizeExtension(t *testing.T) {
	for in, want := range map[string]string{
		"doc": ".doc", ".doc": ".doc", "TAR.GZ": ".tar.gz", ".Z": ".z",
	} {
		if got := NormalizeExtension(in); got != want {
			t.Errorf("NormalizeExtension(%q): got %q want %q", in, got, want)
		}
	}
}

func TestScanTranslatesUniversalNewlines(t *testing.T) {
	dir := t.TempDir()
	// CRLF and a lone CR must both become one line each.
	p := writeFile(t, dir, "crlf.txt", "a=1\r\nb=2\rc=3\n")
	rs := New(false, nil)
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Lines != 3 {
		t.Errorf("lines: got %d want 3", stats.Lines)
	}
	if len(found) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(found))
	}
	oc := match.NewOutputConfig(false, false, false)
	// The \r must not survive into the value.
	if v := found[0].Value(oc); v == nil || *v != "1" {
		t.Errorf("CR must be translated out of the line: got %v", v)
	}
}

// $-anchored patterns depend on the line retaining its trailing newline.
func TestScanRetainsTrailingNewlineForDollarAnchors(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "k.pem", "-----BEGIN RSA PRIVATE KEY-----\n")
	pk, err := rake.NewPattern(rake.PatternOpts{
		Name: "RakePattern", PType: "private key", PDesc: "d", Severity: "HIGH",
		Pattern: `^(-----BEGIN ([A-Z0-9]{2,} )?PRIVATE KEY-----$)`,
		CtxGroup: ip(0), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := New(false, []string{})
	if err := rs.Add(pk); err != nil {
		t.Fatal(err)
	}
	found, _, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("$ must match before the trailing newline, got %d findings", len(found))
	}
}

func TestScanRecordsDetectedEncoding(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "a.txt", "plain ascii content here\n")
	rs := New(false, nil)
	ctx := ctxFor(dir, p)
	if _, _, err := rs.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if ctx.Encoding == "" {
		t.Error("Scan must record the detected encoding on the context")
	}
}

func TestScanUndecodableFileReportsZeroLines(t *testing.T) {
	dir := t.TempDir()
	// Invalid UTF-8 that chardet will not map to a decodable charset.
	p := filepath.Join(dir, "bin.txt")
	if err := os.WriteFile(p, []byte{0x41, 0x42, 0xff, 0xfe, 0xff, 0xfe, 0x43}, 0o644); err != nil {
		t.Fatal(err)
	}
	rs := New(false, []string{})
	_, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	// Python zeroes lineno in the UnicodeDecodeError handler; preserved.
	if stats.Lines != 0 {
		t.Errorf("an undecodable file must report 0 lines, got %d", stats.Lines)
	}
}

func TestScanMissingFileIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	rs := New(false, []string{})
	found, stats, err := rs.Scan(ctxFor(dir, filepath.Join(dir, "gone.txt")))
	if err != nil {
		t.Fatalf("a missing file must not be a hard error: %v", err)
	}
	if len(found) != 0 || stats.Files != 0 {
		t.Error("a missing file must yield nothing")
	}
}

func TestScanAppliesFileMetaRakes(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "id_rsa", "not really a key\n")
	fm, err := rake.NewFileMeta(rake.FileMetaOpts{
		PType: "ssh identity file", PDesc: "d", Severity: "HIGH",
		File: sp("^id_(rsa1?|dsa|ecdsa|ed25519)$"), All: false, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := New(false, []string{})
	if err := rs.Add(fm); err != nil {
		t.Fatal(err)
	}
	found, stats, err := rs.Scan(ctxFor(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 filemeta finding, got %d", len(found))
	}
	if found[0].Line() != nil {
		t.Error("a filemeta finding carries no line")
	}
	if stats.Hits != 1 {
		t.Errorf("hits: got %d want 1", stats.Hits)
	}
}

func TestStatsAdd(t *testing.T) {
	a := Stats{Files: 1, Lines: 2, Hits: 3, Bytes: 4}
	a.Add(Stats{Files: 10, Lines: 20, Hits: 30, Bytes: 40})
	if a != (Stats{Files: 11, Lines: 22, Hits: 33, Bytes: 44}) {
		t.Errorf("Add: got %#v", a)
	}
}

func TestScanIsSafeForConcurrentUse(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 24; i++ {
		paths = append(paths, writeFile(t, dir, string(rune('a'+i))+".properties", "password=hunter2\n"))
	}
	rs := New(false, []string{})
	if err := rs.Add(pwPattern(t)); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, len(paths))
	for _, p := range paths {
		go func(p string) {
			found, _, err := rs.Scan(ctxFor(dir, p))
			if err != nil {
				done <- -1
				return
			}
			done <- len(found)
		}(p)
	}
	for range paths {
		if n := <-done; n != 1 {
			t.Fatalf("concurrent scan returned %d findings", n)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./rakeset/ -v`
Expected: FAIL — `undefined: New`, `undefined: Stats`.

- [ ] **Step 3: Write the implementation**

```go
// Package rakeset applies a collection of rakes to files.
package rakeset

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/walker"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/transform"
)

// encodingSampleSize is how many bytes are sampled for charset detection.
// Detection is accurate on a small sample and we do not want to read entire
// files just to guess.
const encodingSampleSize = 2048

// DefaultExcludeExtensions mirrors RakeSet.DEFAULT_BLACKLIST (common.py:472):
// binary and archive types that are never worth reading. Replaced wholesale by
// DirectoryWalker.ExcludeFileExtensions when the config supplies it.
var DefaultExcludeExtensions = []string{
	".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
	".tiff", ".zip", ".doc", ".docx", ".xls", ".xlsx",
	".pdf", ".tar", ".tgz", ".gz", ".tar.gz",
	".jar", ".war", ".ear", ".class", ".css",
}

// Stats holds per-file or accumulated counters.
type Stats struct {
	Files int64
	Lines int64
	Hits  int64
	Bytes int64
}

func (s *Stats) Add(o Stats) {
	s.Files += o.Files
	s.Lines += o.Lines
	s.Hits += o.Hits
	s.Bytes += o.Bytes
}

// RakeSet is a collection of rakes applied to every file scanned. It is
// read-only once built, so Scan may run on many goroutines at once.
type RakeSet struct {
	contentRakes []rake.ContentRake
	metaRakes    []rake.MetaRake
	verbose      bool
	excludeExts  []string
}

// New builds a RakeSet. A nil excludeExtensions uses DefaultExcludeExtensions;
// an empty non-nil slice excludes nothing.
func New(verbose bool, excludeExtensions []string) *RakeSet {
	exts := DefaultExcludeExtensions
	if excludeExtensions != nil {
		exts = make([]string, 0, len(excludeExtensions))
		for _, e := range excludeExtensions {
			exts = append(exts, NormalizeExtension(e))
		}
	}
	return &RakeSet{verbose: verbose, excludeExts: exts}
}

// NormalizeExtension lowercases and ensures a leading dot, so config entries
// ("doc") and the hardcoded defaults (".doc") compare identically. Multi-part
// entries such as "tar.gz" work because matching is a suffix test.
func NormalizeExtension(e string) string {
	e = strings.ToLower(e)
	if e == "" {
		return ""
	}
	if !strings.HasPrefix(e, ".") {
		e = "." + e
	}
	return e
}

// Add files a rake into the content or metadata list based on its part.
func (rs *RakeSet) Add(r any) error {
	if rs.verbose {
		fmt.Fprintf(os.Stderr, "* Adding new Rake: %v\n", r)
	}
	switch t := r.(type) {
	case rake.MetaRake:
		if t.Part() == rake.PartFileMeta {
			rs.metaRakes = append(rs.metaRakes, t)
			return nil
		}
	case rake.ContentRake:
		if t.Part() == rake.PartContent {
			rs.contentRakes = append(rs.contentRakes, t)
			return nil
		}
	}
	// A ContentRake also satisfies MetaRake's method set in some shapes, so
	// re-check the other direction before giving up.
	if cr, ok := r.(rake.ContentRake); ok && cr.Part() == rake.PartContent {
		rs.contentRakes = append(rs.contentRakes, cr)
		return nil
	}
	return fmt.Errorf("unknown rake type: %T", r)
}

func (rs *RakeSet) ContentCount() int { return len(rs.contentRakes) }
func (rs *RakeSet) MetaCount() int    { return len(rs.metaRakes) }

// MatchContext applies the metadata rakes once per file.
func (rs *RakeSet) MatchContext(ctx *walker.Context) ([]*match.RakeMatch, error) {
	var hits []*match.RakeMatch
	for _, r := range rs.metaRakes {
		// Each rake's MatchContext applies its own filters and returns nil on
		// no-match; we only collect.
		rm, err := r.MatchContext(ctx)
		if err != nil {
			return nil, err
		}
		if rm == nil {
			continue
		}
		hits = append(hits, rm)
	}
	return hits, nil
}

// MatchContent applies the content rakes to one line.
func (rs *RakeSet) MatchContent(ctx *walker.Context, text string) ([]*match.RakeMatch, error) {
	var out []*match.RakeMatch
	for _, r := range rs.contentRakes {
		if rs.verbose {
			fmt.Fprintf(os.Stderr, "using rake: %s at %s: %s", r.Name(), ctx.FullPath, text)
		}
		mset, err := r.Match(ctx, text)
		if err != nil {
			return nil, err
		}
		for _, m := range mset {
			// Python filters again here (common.py:466) even though Match has
			// already applied the chain. Filters are pure and idempotent, so
			// this only costs work; kept so the surviving set is identical.
			if !r.Filter(m) {
				continue
			}
			out = append(out, m)
		}
	}
	return out, nil
}

// excluded reports whether the filename ends with an excluded extension.
// Matching is a case-insensitive suffix test, as at common.py:540.
func (rs *RakeSet) excluded(filename string) (string, bool) {
	lower := strings.ToLower(filename)
	for _, ext := range rs.excludeExts {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(lower, ext) {
			return ext, true
		}
	}
	return "", false
}

// detectEncoding samples the head of a file and guesses its charset. Returns
// "" when the file cannot be read or is empty.
//
// Go's detector is not Python's chardet, so the guess may differ on non-UTF-8
// input. UTF-8 and ASCII are unaffected.
func detectEncoding(fullpath string) string {
	f, err := os.Open(fullpath)
	if err != nil {
		return ""
	}
	defer f.Close()

	buf := make([]byte, encodingSampleSize)
	n, err := io.ReadFull(f, buf)
	if n == 0 {
		return ""
	}
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}

	res, err := chardet.NewTextDetector().DetectBest(buf[:n])
	if err != nil || res == nil {
		return ""
	}
	return res.Charset
}

// decoderFor resolves a charset name to a decoding transformer. An unknown or
// empty name yields nil, meaning "treat the bytes as UTF-8", matching the
// codecs.lookup fallback at common.py:559.
func decoderFor(name string) transform.Transformer {
	if name == "" {
		return nil
	}
	enc, err := ianaindex.IANA.Encoding(name)
	if err != nil || enc == nil {
		return nil
	}
	return enc.NewDecoder()
}

// lineReader yields lines with Python's universal-newline behavior: \r\n and a
// lone \r both become \n, and each line keeps its trailing \n. That terminator
// matters because $-anchored patterns rely on it.
type lineReader struct {
	r *bufio.Reader
}

func (l *lineReader) readLine() (string, error) {
	var sb strings.Builder
	for {
		r, _, err := l.r.ReadRune()
		if err != nil {
			if sb.Len() > 0 && err == io.EOF {
				// Final line with no terminator.
				return sb.String(), nil
			}
			return "", err
		}

		switch r {
		case '\n':
			sb.WriteByte('\n')
			return sb.String(), nil
		case '\r':
			// Consume a following \n so CRLF counts as one terminator.
			if nr, _, err2 := l.r.ReadRune(); err2 == nil && nr != '\n' {
				_ = l.r.UnreadRune()
			}
			sb.WriteByte('\n')
			return sb.String(), nil
		default:
			sb.WriteRune(r)
		}
	}
}

// Scan scans one file and returns its findings and counters.
//
// It mutates no RakeSet state and writes no output, so it is safe to call
// concurrently. Each Context is produced fresh by the walker and owned by the
// goroutine scanning it, so mutating ctx.LineNo and ctx.Encoding needs no lock.
func (rs *RakeSet) Scan(ctx *walker.Context) ([]*match.RakeMatch, Stats, error) {
	var stats Stats
	var findings []*match.RakeMatch

	if rs.verbose {
		fmt.Fprintf(os.Stderr, "* New context: %s\n", ctx.FullPath)
	}

	if ctx.Path == "" || ctx.Filename == "" {
		if rs.verbose {
			fmt.Fprintln(os.Stderr, "* Context is invalid?")
		}
		return nil, stats, nil
	}

	if ext, skip := rs.excluded(ctx.Filename); skip {
		if rs.verbose {
			fmt.Fprintf(os.Stderr, "* File matches blacklisted extension: %s\n", ext)
		}
		return nil, stats, nil
	}

	if rs.verbose {
		fmt.Fprintln(os.Stderr, "* Applying context Rakes")
	}
	metaHits, err := rs.MatchContext(ctx)
	if err != nil {
		return nil, stats, err
	}
	findings = append(findings, metaHits...)

	enc := detectEncoding(ctx.FullPath)
	if enc == "" {
		enc = "utf-8"
	}
	ctx.Encoding = enc

	f, err := os.Open(ctx.FullPath)
	if err != nil {
		if rs.verbose {
			fmt.Fprintf(os.Stderr, "* Unable to open file: %s\n", ctx.FullPath)
		}
		// Python returns what it has so far; a missing file is not fatal.
		return findings, stats, nil
	}
	defer f.Close()

	// Chain the charset decoder with a UTF-8 validator so undecodable input
	// surfaces as an error, reproducing Python's UnicodeDecodeError rather than
	// silently substituting replacement characters.
	var src io.Reader = f
	if dec := decoderFor(enc); dec != nil {
		src = transform.NewReader(f, transform.Chain(dec, encoding.UTF8Validator))
	} else {
		src = transform.NewReader(f, encoding.UTF8Validator)
	}

	if rs.verbose {
		fmt.Fprintln(os.Stderr, "* Applying content Rakes")
	}

	lr := &lineReader{r: bufio.NewReader(src)}
	lineno := 0
	decodeFailed := false

	for {
		line, err := lr.readLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Cannot process this file due to encoding -- skip the rest.
			// Python discards the count entirely (common.py:590).
			decodeFailed = true
			break
		}

		lineno++
		if rs.verbose && lineno%100 == 0 {
			fmt.Fprintf(os.Stderr, "* %d lines processed (%s)\n", lineno, ctx.FullPath)
		}

		ctx.LineNo = &lineno
		hits, err := rs.MatchContent(ctx, line)
		if err != nil {
			return nil, stats, err
		}
		findings = append(findings, hits...)
	}

	stats.Files = 1
	stats.Lines = int64(lineno)
	if decodeFailed {
		stats.Lines = 0
	}
	stats.Hits = int64(len(findings))

	if fi, err := os.Stat(ctx.FullPath); err == nil {
		stats.Bytes = fi.Size()
	}

	return findings, stats, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./rakeset/ -v && go test -race ./rakeset/ -run Concurrent`
Expected: PASS. The `-race` run must report no data races.

Note on `ctx.LineNo = &lineno`: taking the address of the loop-scoped counter
is intentional and safe because each `RakeMatch` copies the pointed-to value
into its own field when constructed. If a race or stale-value failure appears,
change to `n := lineno; ctx.LineNo = &n`.

- [ ] **Step 5: Commit**

```bash
git add golang/rakeset/
git commit -m "feat(golang): add RakeSet with encoding detection and line scanning

Scan mutates no shared state and writes no output, so it is safe to call
from many goroutines. Reports the true line count rather than Python's N+1,
and preserves zeroing the count when a file cannot be decoded.

Universal-newline translation reproduces Python text mode: CRLF and lone CR
become LF, and each line keeps its terminator so \$-anchored patterns match.
A UTF8Validator is chained after the charset decoder so undecodable input
errors instead of yielding replacement characters."
```

---

### Task 13: `writer` package — `DataRakeWriter` interface and `CSVWriter`

**Files:**
- Create: `golang/writer/datarakewriter.go`, `golang/writer/csvwriter.go`
- Test: `golang/writer/csvwriter_test.go`

**Interfaces:**
- Consumes: `match.RakeMatch`, `match.OutputConfig` (Task 2); `rakeset.Stats` (Task 12).
- Produces:
  - `type Summary struct { Files, Lines, Hits, Bytes int64 }`
  - `type DataRakeWriter interface { InitOutput() error; InitSecrets() error; WriteSecret(*match.RakeMatch) error; EndSecrets() error; InitSummary() error; WriteSummary(Summary) error; EndSummary() error; EndOutput() error }`
  - `type Opts struct { W io.Writer; Quiet, Summary bool; Output *match.OutputConfig }`
  - `func NewCSVWriter(o Opts) *CSVWriter`
  - `func CSVField(s string) string`

**Note.** Go's `encoding/csv` cannot be used: it quotes any field with leading
whitespace, which Python does not, and a context can legitimately begin with a
space. This writer quotes only when the field contains a comma, a double quote,
CR or LF — Python's `QUOTE_MINIMAL` — and terminates rows with CRLF.

- [ ] **Step 1: Write the failing test**

```go
package writer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jcwoods/datarake/golang/match"
)

type fakeRake struct{ t, d, s string }

func (f fakeRake) PType() string    { return f.t }
func (f fakeRake) PDesc() string    { return f.d }
func (f fakeRake) Severity() string { return f.s }

func ip(i int) *int { return &i }

func sampleMatch() *match.RakeMatch {
	m := match.New(fakeRake{"password", "possible plaintext password", "HIGH"}, "src/a.properties", ip(2))
	m.SetContext("password=Sup3rSekrit!", 0, 20)
	m.SetValue("Sup3rSekrit!", 9, 12)
	return m
}

func TestCSVFieldQuotesOnlyWhatPythonQuotes(t *testing.T) {
	cases := map[string]string{
		"plain":                 "plain",
		"  leading spaces":      "  leading spaces",   // Python does NOT quote
		"trailing spaces  ":     "trailing spaces  ",  // nor these
		"has,comma":             `"has,comma"`,
		`has"quote`:             `"has""quote"`,
		"has\nnewline":          "\"has\nnewline\"",
		"has\rcr":               "\"has\rcr\"",
		"":                      "",
	}
	for in, want := range cases {
		if got := CSVField(in); got != want {
			t.Errorf("CSVField(%q): got %q want %q", in, got, want)
		}
	}
}

func TestCSVWriterEmitsHeaderAndRowWithCRLF(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Output: oc})

	for _, step := range []func() error{
		w.InitOutput, w.InitSecrets,
		func() error { return w.WriteSecret(sampleMatch()) },
		w.EndSecrets, w.InitSummary,
		func() error { return w.WriteSummary(Summary{}) },
		w.EndSummary, w.EndOutput,
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}

	got := buf.String()
	lines := strings.Split(strings.TrimSuffix(got, "\r\n"), "\r\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 row, got %d lines from %q", len(lines), got)
	}
	wantHeader := "file,line,label,severity,description," +
		"value_offset,value_length,value,context_offset,context_length,context"
	if lines[0] != wantHeader {
		t.Errorf("header:\n got %q\nwant %q", lines[0], wantHeader)
	}
	wantRow := "src/a.properties,2,password,HIGH,possible plaintext password," +
		"9,12,Sup3rSekrit!,0,20,password=Sup3rSekrit!"
	if lines[1] != wantRow {
		t.Errorf("row:\n got %q\nwant %q", lines[1], wantRow)
	}
}

func TestCSVWriterQuietSuppressesHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Quiet: true, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	if buf.Len() != 0 {
		t.Errorf("quiet mode must emit nothing, got %q", buf.String())
	}
}

func TestCSVWriterSummaryFormat(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Quiet: true, Summary: true, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.EndSecrets()
	w.InitSummary()
	if err := w.WriteSummary(Summary{Files: 3, Lines: 40, Hits: 5, Bytes: 900}); err != nil {
		t.Fatal(err)
	}
	w.EndSummary()
	w.EndOutput()

	want := "files: 3\nlines: 40\nbytes: 900\nhits: 5\n"
	if buf.String() != want {
		t.Errorf("summary:\n got %q\nwant %q", buf.String(), want)
	}
}

func TestCSVWriterSummaryDisabledEmitsNothing(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewCSVWriter(Opts{W: &buf, Quiet: true, Summary: false, Output: oc})
	w.InitSummary()
	w.WriteSummary(Summary{Files: 1})
	w.EndSummary()
	if buf.Len() != 0 {
		t.Errorf("summary must be suppressed, got %q", buf.String())
	}
}

func TestCSVWriterSecureModeDropsValueColumn(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(true, false, false)
	w := NewCSVWriter(Opts{W: &buf, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\r\n"), "\r\n")
	if strings.Contains(lines[0], ",value,") {
		t.Errorf("secure mode must drop the value column: %q", lines[0])
	}
	if strings.Contains(lines[1], "Sup3rSekrit!") {
		t.Errorf("secure mode leaked the secret: %q", lines[1])
	}
	if !strings.Contains(lines[0], "context") {
		t.Errorf("secure mode must keep the context column: %q", lines[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./writer/ -v`
Expected: FAIL — `undefined: NewCSVWriter`, `undefined: CSVField`, `undefined: Opts`.

- [ ] **Step 3: Write `datarakewriter.go`**

```go
// Package writer renders findings in the supported output formats.
package writer

import (
	"io"

	"github.com/jcwoods/datarake/golang/match"
)

// Summary carries the run totals. Field order matches the JSON key order that
// json.dumps produces from the totals dict (files, lines, hits, bytes).
type Summary struct {
	Files int64
	Lines int64
	Hits  int64
	Bytes int64
}

// DataRakeWriter is the output contract. The lifecycle is:
//
//	InitOutput -> InitSecrets -> WriteSecret* -> EndSecrets ->
//	InitSummary -> WriteSummary -> EndSummary -> EndOutput
//
// Implementations are used only from the main goroutine.
type DataRakeWriter interface {
	InitOutput() error
	InitSecrets() error
	WriteSecret(m *match.RakeMatch) error
	EndSecrets() error
	InitSummary() error
	WriteSummary(s Summary) error
	EndSummary() error
	EndOutput() error
}

// Opts configures a writer.
type Opts struct {
	W       io.Writer
	Quiet   bool // suppress findings, summary only
	Summary bool // emit the summary block
	Output  *match.OutputConfig
}
```

- [ ] **Step 4: Write `csvwriter.go`**

```go
package writer

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/jcwoods/datarake/golang/match"
)

// CSVWriter emits findings as CSV.
//
// encoding/csv is deliberately not used: it quotes any field with leading or
// trailing whitespace, which Python's csv.writer does not, and a context can
// legitimately begin with a space.
type CSVWriter struct {
	o  Opts
	bw *bufio.Writer
}

func NewCSVWriter(o Opts) *CSVWriter {
	return &CSVWriter{o: o, bw: bufio.NewWriter(o.W)}
}

// CSVField applies Python's QUOTE_MINIMAL: quote only when the field contains
// the delimiter, a double quote, CR or LF, doubling embedded quotes.
func CSVField(s string) string {
	if strings.ContainsAny(s, ",\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// writeRow emits one CRLF-terminated record.
func (w *CSVWriter) writeRow(fields []string) error {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = CSVField(f)
	}
	_, err := w.bw.WriteString(strings.Join(out, ",") + "\r\n")
	return err
}

func (w *CSVWriter) InitOutput() error { return nil }

func (w *CSVWriter) InitSecrets() error {
	if w.o.Quiet {
		return nil
	}
	return w.writeRow(w.o.Output.Header())
}

func (w *CSVWriter) WriteSecret(m *match.RakeMatch) error {
	if w.o.Quiet {
		return nil
	}
	return w.writeRow(m.AsRecord(w.o.Output))
}

func (w *CSVWriter) EndSecrets() error { return w.bw.Flush() }

func (w *CSVWriter) InitSummary() error { return nil }

// WriteSummary emits plain "key: value" lines rather than CSV records,
// matching DataRakeCSVWriter.writeSummary. Order is files, lines, bytes, hits.
func (w *CSVWriter) WriteSummary(s Summary) error {
	if !w.o.Summary {
		return nil
	}
	for _, line := range []string{
		fmt.Sprintf("files: %d", s.Files),
		fmt.Sprintf("lines: %d", s.Lines),
		fmt.Sprintf("bytes: %d", s.Bytes),
		fmt.Sprintf("hits: %d", s.Hits),
	} {
		if _, err := w.bw.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.bw.Flush()
}

func (w *CSVWriter) EndSummary() error { return w.bw.Flush() }
func (w *CSVWriter) EndOutput() error  { return w.bw.Flush() }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd golang && go test ./writer/ -v`
Expected: PASS, all six tests.

- [ ] **Step 6: Commit**

```bash
git add golang/writer/datarakewriter.go golang/writer/csvwriter.go golang/writer/csvwriter_test.go
git commit -m "feat(golang): add DataRakeWriter interface and CSVWriter

Hand-rolled CSV quoting rather than encoding/csv, which quotes fields with
leading whitespace where Python does not. Rows are CRLF-terminated and the
summary is emitted as plain key: value lines, both matching Python."
```

---

### Task 14: `writer` package — `JSONWriter`

**Files:**
- Create: `golang/writer/jsonwriter.go`
- Test: `golang/writer/jsonwriter_test.go`

**Interfaces:**
- Consumes: `Opts`, `Summary`, `DataRakeWriter` (Task 13); `match.RakeMatch`.
- Produces:
  - `func NewJSONWriter(o Opts) *JSONWriter`
  - `func JSONString(s string) string` — Python `json.dumps` string semantics

**Why hand-rolled.** `encoding/json` differs from Python's defaults in three
ways, all verified against both implementations:

```
input: {'path': 'héllo/日本.txt', 'context': 'a<b>c&d'}

py:    {"path": "h\u00e9llo/\u65e5\u672c.txt", "context": "a<b>c&d"}
go:    {"path":"héllo/日本.txt","context":"a\u003cb\u003ec\u0026d"}
```

Python uses `", "`/`": "` separators, escapes non-ASCII (`ensure_ascii=True`),
and leaves `<>&` literal. Go does the opposite on all three. Objects are
therefore emitted field by field with explicit separators.

- [ ] **Step 1: Write the failing test**

```go
package writer

import (
	"bytes"
	"testing"

	"github.com/jcwoods/datarake/golang/match"
)

func TestJSONStringMatchesPythonJsonDumps(t *testing.T) {
	cases := map[string]string{
		"plain":        `"plain"`,
		`with"quote`:   `"with\"quote"`,
		`back\slash`:   `"back\\slash"`,
		"tab\there":    `"tab\there"`,
		"nl\nhere":     `"nl\nhere"`,
		"cr\rhere":     `"cr\rhere"`,
		// Python leaves these literal; encoding/json would escape them.
		"a<b>c&d":      `"a<b>c&d"`,
		// ensure_ascii=True escapes non-ASCII, including DEL.
		"héllo":        `"h\u00e9llo"`,
		"日本":           `"\u65e5\u672c"`,
		"\x7f":         `"\u007f"`,
		"\x01":         `"\u0001"`,
		// Astral plane becomes a surrogate pair.
		"\U0001F600":   `"\ud83d\ude00"`,
	}
	for in, want := range cases {
		if got := JSONString(in); got != want {
			t.Errorf("JSONString(%q):\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestJSONWriterFullDocument(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewJSONWriter(Opts{W: &buf, Summary: true, Output: oc})

	if err := w.InitOutput(); err != nil {
		t.Fatal(err)
	}
	w.InitSecrets()
	if err := w.WriteSecret(sampleMatch()); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteSecret(sampleMatch()); err != nil {
		t.Fatal(err)
	}
	w.EndSecrets()
	w.InitSummary()
	w.WriteSummary(Summary{Files: 1, Lines: 2, Hits: 2, Bytes: 46})
	w.EndSummary()
	if err := w.EndOutput(); err != nil {
		t.Fatal(err)
	}

	secret := `{"path": "src/a.properties", "line": 2, "type": "password", ` +
		`"description": "possible plaintext password", "severity": "HIGH", ` +
		`"context": {"value": "password=Sup3rSekrit!", "offset": 0, "length": 20}, ` +
		`"value": {"value": "Sup3rSekrit!", "offset": 9, "length": 12}}`
	// Note the summary key order: files, lines, hits, bytes -- the insertion
	// order of the totals dict, which differs from the CSV summary's order.
	want := `{"secrets": [` + secret + `,` + secret + `],"summary": ` +
		`{"files": 1, "lines": 2, "hits": 2, "bytes": 46}}` + "\n"

	if buf.String() != want {
		t.Errorf("document mismatch:\n got %s\nwant %s", buf.String(), want)
	}
}

func TestJSONWriterNullLineForFileMeta(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewJSONWriter(Opts{W: &buf, Output: oc})
	m := match.New(fakeRake{"ssh identity file", "d", "HIGH"}, "id_rsa", nil)

	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(m)
	w.EndSecrets()
	w.EndOutput()

	want := `{"secrets": [{"path": "id_rsa", "line": null, "type": "ssh identity file", ` +
		`"description": "d", "severity": "HIGH", ` +
		`"context": {"value": null, "offset": null, "length": null}, ` +
		`"value": {"value": null, "offset": null, "length": null}}]}` + "\n"
	if buf.String() != want {
		t.Errorf("mismatch:\n got %s\nwant %s", buf.String(), want)
	}
}

func TestJSONWriterQuietWithSummaryOmitsSecretsKey(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, false, false)
	w := NewJSONWriter(Opts{W: &buf, Quiet: true, Summary: true, Output: oc})

	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	w.InitSummary()
	w.WriteSummary(Summary{Files: 1})
	w.EndSummary()
	w.EndOutput()

	// No leading comma: _keys_written stays 0 because InitSecrets returned early.
	want := `{"summary": {"files": 1, "lines": 0, "hits": 0, "bytes": 0}}` + "\n"
	if buf.String() != want {
		t.Errorf("mismatch:\n got %s\nwant %s", buf.String(), want)
	}
}

func TestJSONWriterDisableContextOmitsContextObject(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(false, true, false)
	w := NewJSONWriter(Opts{W: &buf, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	w.EndOutput()

	got := buf.String()
	if bytes.Contains([]byte(got), []byte(`"context"`)) {
		t.Errorf("disable-context must omit the context object: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte(`"value"`)) {
		t.Errorf("the value object must remain: %s", got)
	}
}

func TestJSONWriterSecureModeHashesContextAndNullsValue(t *testing.T) {
	var buf bytes.Buffer
	oc := match.NewOutputConfig(true, false, false)
	w := NewJSONWriter(Opts{W: &buf, Output: oc})
	w.InitOutput()
	w.InitSecrets()
	w.WriteSecret(sampleMatch())
	w.EndSecrets()
	w.EndOutput()

	got := buf.String()
	if bytes.Contains([]byte(got), []byte("Sup3rSekrit!")) {
		t.Errorf("secure mode leaked the secret: %s", got)
	}
	if !bytes.Contains([]byte(got), []byte(`"value": {"value": null`)) {
		t.Errorf("secure mode must null the value: %s", got)
	}
	if bytes.Contains([]byte(got), []byte("password=Sup3rSekrit!")) {
		t.Errorf("secure mode must hash the context: %s", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./writer/ -run JSON -v`
Expected: FAIL — `undefined: NewJSONWriter`, `undefined: JSONString`.

- [ ] **Step 3: Write the implementation**

```go
package writer

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/jcwoods/datarake/golang/match"
)

// JSONWriter streams a single JSON document.
//
// encoding/json is not used because Python's json.dumps differs from it in
// three ways that all show up in output: separator spacing (", " and ": "),
// non-ASCII escaping (ensure_ascii=True), and HTML escaping (Go escapes
// <, > and &; Python does not).
type JSONWriter struct {
	o  Opts
	bw *bufio.Writer

	count       int // secrets written so far
	keysWritten int // top-level keys written so far
}

func NewJSONWriter(o Opts) *JSONWriter {
	return &JSONWriter{o: o, bw: bufio.NewWriter(o.W)}
}

// JSONString renders a Go string exactly as Python's json.dumps would with
// default options: escape the quote and backslash, use short escapes for the
// five control characters that have them, and escape everything outside
// printable ASCII (0x20-0x7e) as \uXXXX, with surrogate pairs above the BMP.
func JSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')

	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
				continue
			}
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
				continue
			}
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}

	b.WriteByte('"')
	return b.String()
}

// jsonNumOrNull renders an optional integer.
func jsonNumOrNull(p *int) string {
	if p == nil {
		return "null"
	}
	return strconv.Itoa(*p)
}

// jsonStrOrNull renders an optional string.
func jsonStrOrNull(p *string) string {
	if p == nil {
		return "null"
	}
	return JSONString(*p)
}

func (w *JSONWriter) InitOutput() error {
	w.count = 0
	w.keysWritten = 0
	_, err := w.bw.WriteString("{")
	return err
}

func (w *JSONWriter) InitSecrets() error {
	if w.o.Quiet {
		return nil
	}
	w.keysWritten++
	_, err := w.bw.WriteString(`"secrets": [`)
	return err
}

// WriteSecret emits one finding. Keys are written in the insertion order of
// RakeMatch.asdict: path, line, type, description, severity, context, value.
func (w *JSONWriter) WriteSecret(m *match.RakeMatch) error {
	if w.o.Quiet {
		return nil
	}
	if w.count > 0 {
		if _, err := w.bw.WriteString(","); err != nil {
			return err
		}
	}

	var b strings.Builder
	b.WriteString("{")
	b.WriteString(`"path": ` + JSONString(m.File()))

	line := "null"
	if m.Line() != nil {
		line = strconv.Itoa(*m.Line())
	}
	b.WriteString(`, "line": ` + line)
	b.WriteString(`, "type": ` + JSONString(m.Label()))
	b.WriteString(`, "description": ` + JSONString(m.Description()))
	b.WriteString(`, "severity": ` + JSONString(m.Severity()))

	if !w.o.Output.DisableContext() {
		b.WriteString(`, "context": {"value": ` + jsonStrOrNull(m.Context(w.o.Output)))
		b.WriteString(`, "offset": ` + jsonNumOrNull(m.ContextOffset()))
		b.WriteString(`, "length": ` + jsonNumOrNull(m.ContextLength()) + "}")
	}

	if !w.o.Output.DisableValue() {
		b.WriteString(`, "value": {"value": ` + jsonStrOrNull(m.Value(w.o.Output)))
		b.WriteString(`, "offset": ` + jsonNumOrNull(m.ValueOffset()))
		b.WriteString(`, "length": ` + jsonNumOrNull(m.ValueLength()) + "}")
	}

	b.WriteString("}")

	if _, err := w.bw.WriteString(b.String()); err != nil {
		return err
	}
	w.count++
	return nil
}

func (w *JSONWriter) EndSecrets() error {
	if w.o.Quiet {
		return nil
	}
	_, err := w.bw.WriteString("]")
	return err
}

func (w *JSONWriter) InitSummary() error {
	if !w.o.Summary {
		return nil
	}
	if w.keysWritten > 0 {
		if _, err := w.bw.WriteString(","); err != nil {
			return err
		}
	}
	w.keysWritten++
	_, err := w.bw.WriteString(`"summary": `)
	return err
}

// WriteSummary emits the totals. Key order is the insertion order of the
// totals dict in main(): files, lines, hits, bytes.
func (w *JSONWriter) WriteSummary(s Summary) error {
	if !w.o.Summary {
		return nil
	}
	_, err := fmt.Fprintf(w.bw,
		`{"files": %d, "lines": %d, "hits": %d, "bytes": %d}`,
		s.Files, s.Lines, s.Hits, s.Bytes)
	return err
}

func (w *JSONWriter) EndSummary() error { return nil }

func (w *JSONWriter) EndOutput() error {
	if _, err := w.bw.WriteString("}\n"); err != nil {
		return err
	}
	return w.bw.Flush()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd golang && go test ./writer/ -v`
Expected: PASS, all tests from Tasks 13–14.

- [ ] **Step 5: Commit**

```bash
git add golang/writer/jsonwriter.go golang/writer/jsonwriter_test.go
git commit -m "feat(golang): add JSONWriter with Python-compatible escaping

Hand-rolled emission rather than encoding/json, which differs from Python's
json.dumps on separator spacing, non-ASCII escaping and HTML escaping.
Keys follow dict insertion order; the summary orders files, lines, hits,
bytes, which is not the CSV summary's order."
```

---

### Task 15: `config` package — `Load`, filter registry, dormant-section wiring

**Files:**
- Create: `golang/config/config.go`
- Test: `golang/config/config_test.go`, `golang/config/yamlrakes_test.go`

**Interfaces:**
- Consumes: everything from Tasks 3–13.
- Produces:
  - `type Global struct { IgnorePasswords, IgnoreUsers, IgnoreHosts, CommonTLDs []string }`
  - `type WalkerConfig struct { ExcludeSubdirs, ExcludeFileExtensions []string }`
  - `type Config struct { Verbose bool; Global Global; Walker WalkerConfig; RakeSet *rakeset.RakeSet }`
  - `func Load(data []byte, timeout time.Duration) (*Config, error)`
  - `func LoadFile(path string, timeout time.Duration) (*Config, error)`

- [ ] **Step 1: Write the failing test — `config_test.go`**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/rakeset"
)

func loadYAML(t *testing.T, body string) *Config {
	t.Helper()
	c, err := Load([]byte(body), time.Second)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestLoadDispatchesAllThreeRakeTypes(t *testing.T) {
	c := loadYAML(t, `
Rakes:
- name: meta
  type: FileMeta
  description: d
  severity: HIGH
  file: "^id_rsa$"
- name: simple
  type: SimplePattern
  description: d
  severity: HIGH
  pattern: '((\w+)=(\w+))'
  contextgroup: 0
  valgroup: 2
- name: ctx
  type: ContextPattern
  description: d
  severity: LOW
  contexts:
  - context: null
    pattern: '((\w+):(\w+))'
    contextgroup: 0
    valgroup: 2
`)
	if got := c.RakeSet.MetaCount(); got != 1 {
		t.Errorf("meta rakes: got %d want 1", got)
	}
	if got := c.RakeSet.ContentCount(); got != 2 {
		t.Errorf("content rakes: got %d want 2", got)
	}
}

func TestLoadRejectsUnsupportedRakeType(t *testing.T) {
	_, err := Load([]byte(`
Rakes:
- name: x
  type: NotARakeType
  description: d
  severity: LOW
`), time.Second)
	if err == nil {
		t.Error("an unsupported rake type must error")
	}
}

func TestLoadReadsVerbose(t *testing.T) {
	if c := loadYAML(t, "verbose: true\nRakes: []\n"); !c.Verbose {
		t.Error("verbose must be read from the config")
	}
	if c := loadYAML(t, "Rakes: []\n"); c.Verbose {
		t.Error("verbose must default to false")
	}
}

func TestNamedFilterRegistryResolves(t *testing.T) {
	c := loadYAML(t, `
FilterRegistry:
- NamedFilter:
    - name:       ShellVariables
      type:       regex
      key:        null
      value:      '^\$[a-z0-9_]+$'
      ignorecase: true
Rakes:
- name: simple
  type: SimplePattern
  description: d
  severity: HIGH
  pattern: '((\w+)=(\S+))'
  contextgroup: 0
  valgroup: 2
  filters:
  - type: named
    name: ShellVariables
`)
	if c.RakeSet.ContentCount() != 1 {
		t.Fatal("expected one content rake")
	}
}

func TestFilterSetSplitAcrossListEntriesIsMerged(t *testing.T) {
	// The shipped schema splits a FilterSet's name and filters into separate
	// list entries; they must be merged.
	c := loadYAML(t, `
FilterRegistry:
- FilterSet:
  - name: VariablesNotLiteral
  - filters:
    - type:       regex
      key:        null
      value:      '^\$[a-z0-9_]+$'
      ignorecase: true
    - type:       regex
      key:        null
      value:      '^\{\{\s*[a-z0-9_]+\s*\}\}$'
      ignorecase: true
Rakes:
- name: simple
  type: SimplePattern
  description: d
  severity: HIGH
  pattern: '((\w+)=(\S+))'
  contextgroup: 0
  valgroup: 2
  filters:
  - type: set
    name: VariablesNotLiteral
`)
	if c.RakeSet.ContentCount() != 1 {
		t.Fatal("expected one content rake")
	}
}

func TestUnknownFilterRegistryKindErrors(t *testing.T) {
	_, err := Load([]byte(`
FilterRegistry:
- SomethingElse:
    - name: x
Rakes: []
`), time.Second)
	if err == nil {
		t.Error("an unknown FilterRegistry kind must error")
	}
}

func TestFilterRegistryEntriesMustBeSingleKey(t *testing.T) {
	_, err := Load([]byte(`
FilterRegistry:
- NamedFilter:
    - name: a
      type: literal
      value: x
  FilterSet:
    - name: b
Rakes: []
`), time.Second)
	if err == nil {
		t.Error("a multi-key FilterRegistry entry must error")
	}
}

func TestDirectoryWalkerSectionIsHonored(t *testing.T) {
	c := loadYAML(t, `
DirectoryWalker:
  ExcludeSubdirs: [ '.git', '__pycache__' ]
  ExcludeFileExtensions: [ 'doc', 'xls' ]
Rakes: []
`)
	if len(c.Walker.ExcludeSubdirs) != 2 || c.Walker.ExcludeSubdirs[0] != ".git" {
		t.Errorf("ExcludeSubdirs: %#v", c.Walker.ExcludeSubdirs)
	}
	if len(c.Walker.ExcludeFileExtensions) != 2 {
		t.Errorf("ExcludeFileExtensions: %#v", c.Walker.ExcludeFileExtensions)
	}
}

// An absent section must fall back to the hardcoded Python defaults.
func TestAbsentSectionsUseDefaults(t *testing.T) {
	c := loadYAML(t, "Rakes: []\n")
	if len(c.Walker.ExcludeSubdirs) != len(walkerDefaults()) {
		t.Errorf("absent ExcludeSubdirs must default to %v, got %v",
			walkerDefaults(), c.Walker.ExcludeSubdirs)
	}
	if len(c.Walker.ExcludeFileExtensions) != len(rakeset.DefaultExcludeExtensions) {
		t.Errorf("absent ExcludeFileExtensions must default to DEFAULT_BLACKLIST, got %v",
			c.Walker.ExcludeFileExtensions)
	}
	if len(c.Global.CommonTLDs) != len(rake.DefaultTLDs) {
		t.Errorf("absent CommonTLDs must default to DefaultTLDs, got %v", c.Global.CommonTLDs)
	}
}

// An explicitly empty list means "exclude nothing", not "use the defaults".
func TestEmptyListIsHonoredNotDefaulted(t *testing.T) {
	c := loadYAML(t, `
DirectoryWalker:
  ExcludeSubdirs: []
  ExcludeFileExtensions: []
Rakes: []
`)
	if c.Walker.ExcludeSubdirs == nil || len(c.Walker.ExcludeSubdirs) != 0 {
		t.Errorf("an explicit empty list must be preserved, got %#v", c.Walker.ExcludeSubdirs)
	}
	if c.Walker.ExcludeFileExtensions == nil || len(c.Walker.ExcludeFileExtensions) != 0 {
		t.Errorf("an explicit empty list must be preserved, got %#v", c.Walker.ExcludeFileExtensions)
	}
}

func TestGlobalCommonTLDsIsHonored(t *testing.T) {
	c := loadYAML(t, `
Global:
  CommonTLDs: [ 'com', 'net' ]
Rakes: []
`)
	if len(c.Global.CommonTLDs) != 2 {
		t.Errorf("CommonTLDs: %#v", c.Global.CommonTLDs)
	}
}

// These three have no hardcoded Python counterpart, so they are parsed and
// reserved rather than wired to behavior.
func TestReservedGlobalKeysAreParsed(t *testing.T) {
	c := loadYAML(t, `
Global:
  IgnorePasswords: [ 'password' ]
  IgnoreUsers:     [ 'example', 'user' ]
  IgnoreHosts:     [ 'example', 'domain' ]
Rakes: []
`)
	if len(c.Global.IgnorePasswords) != 1 || len(c.Global.IgnoreUsers) != 2 || len(c.Global.IgnoreHosts) != 2 {
		t.Errorf("reserved keys must still be parsed: %#v", c.Global)
	}
}

func TestLoadFileReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("Rakes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yaml"), time.Second); err == nil {
		t.Error("a missing config file must error")
	}
}

func TestLoadInvalidYAMLErrors(t *testing.T) {
	if _, err := Load([]byte("Rakes: [ unclosed"), time.Second); err == nil {
		t.Error("invalid YAML must error")
	}
}
```

- [ ] **Step 2: Write the failing test — `yamlrakes_test.go`**

These are the ported `_YAMLRakesMixin` cases. They load the real embedded
config and are what prove the group-number corrections from Task 1 are right.

```go
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

func ctx(name, ext string, line int) *walker.Context {
	has := ext != ""
	n := line
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

// The literal ENCRYPTED filter must suppress encrypted keys.
func TestPrivateKeyRakeSkipsEncrypted(t *testing.T) {
	c := realConfig(t)
	got := scanLine(t, c, "k.pem", "pem", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
	if m := findByLabel(got, "private key"); m != nil {
		t.Error("an encrypted private key must be filtered")
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
```

Note the `ctx` helper takes three arguments in the content tests and two in the
last test; give it a variadic line parameter:
`func ctx(name, ext string, line ...int) *walker.Context`, defaulting to line 1.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd golang && go test ./config/ -v`
Expected: FAIL — `undefined: Load`, `undefined: Config`.

- [ ] **Step 4: Write the implementation**

```go
// Package config loads the YAML configuration and builds the RakeSet.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/rakeset"
	"github.com/jcwoods/datarake/golang/walker"
)

// Global mirrors the config's Global: section.
//
// CommonTLDs is honored by rake.NewHostname and rake.NewEmail. The other three
// have no counterpart anywhere in the Python -- no code path consumes them or
// anything equivalent -- so they are parsed and reserved rather than wired to
// behavior. Implementing them would add suppression semantics that have never
// existed, which is a feature rather than a port.
type Global struct {
	IgnorePasswords []string // reserved; no behavior
	IgnoreUsers     []string // reserved; no behavior
	IgnoreHosts     []string // reserved; no behavior
	CommonTLDs      []string
}

// WalkerConfig mirrors the config's DirectoryWalker: section. Both keys are
// honored here; in Python they are parsed by nobody and the equivalent values
// sit hardcoded in DirectoryWalker.__init__ and RakeSet.DEFAULT_BLACKLIST.
type WalkerConfig struct {
	ExcludeSubdirs        []string
	ExcludeFileExtensions []string
}

// Config is a loaded configuration.
type Config struct {
	Verbose bool
	Global  Global
	Walker  WalkerConfig
	RakeSet *rakeset.RakeSet
}

// walkerDefaults returns the hardcoded ExcludeSubdirs default.
func walkerDefaults() []string { return walker.DefaultExcludeSubdirs }

// yamlFile mirrors the on-disk schema. Pointers distinguish "key absent" (use
// the default) from "key present but empty" (exclude nothing).
type yamlFile struct {
	Verbose bool `yaml:"verbose"`

	Global *struct {
		IgnorePasswords []string  `yaml:"IgnorePasswords"`
		IgnoreUsers     []string  `yaml:"IgnoreUsers"`
		IgnoreHosts     []string  `yaml:"IgnoreHosts"`
		CommonTLDs      *[]string `yaml:"CommonTLDs"`
	} `yaml:"Global"`

	DirectoryWalker *struct {
		ExcludeSubdirs        *[]string `yaml:"ExcludeSubdirs"`
		ExcludeFileExtensions *[]string `yaml:"ExcludeFileExtensions"`
	} `yaml:"DirectoryWalker"`

	FilterRegistry []map[string][]map[string]any `yaml:"FilterRegistry"`
	Rakes          []map[string]any              `yaml:"Rakes"`
}

// LoadFile reads and parses a configuration file.
func LoadFile(path string, timeout time.Duration) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Load(data, timeout)
}

// Load parses configuration bytes and builds the RakeSet.
func Load(data []byte, timeout time.Duration) (*Config, error) {
	var f yamlFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg := &Config{Verbose: f.Verbose}

	// Global.
	cfg.Global.CommonTLDs = rake.DefaultTLDs
	if f.Global != nil {
		cfg.Global.IgnorePasswords = f.Global.IgnorePasswords
		cfg.Global.IgnoreUsers = f.Global.IgnoreUsers
		cfg.Global.IgnoreHosts = f.Global.IgnoreHosts
		if f.Global.CommonTLDs != nil {
			cfg.Global.CommonTLDs = *f.Global.CommonTLDs
		}
	}

	// DirectoryWalker.
	cfg.Walker.ExcludeSubdirs = walkerDefaults()
	cfg.Walker.ExcludeFileExtensions = rakeset.DefaultExcludeExtensions
	if f.DirectoryWalker != nil {
		if f.DirectoryWalker.ExcludeSubdirs != nil {
			cfg.Walker.ExcludeSubdirs = *f.DirectoryWalker.ExcludeSubdirs
		}
		if f.DirectoryWalker.ExcludeFileExtensions != nil {
			cfg.Walker.ExcludeFileExtensions = *f.DirectoryWalker.ExcludeFileExtensions
		}
	}

	// The registry must be built first so rake filter references resolve.
	reg, err := buildFilterRegistry(f.FilterRegistry, timeout)
	if err != nil {
		return nil, err
	}

	rs := rakeset.New(cfg.Verbose, cfg.Walker.ExcludeFileExtensions)
	for _, r := range f.Rakes {
		if err := addRake(rs, r, reg, timeout); err != nil {
			return nil, err
		}
	}
	cfg.RakeSet = rs

	return cfg, nil
}

// addRake builds one rake and files it into the set.
func addRake(rs *rakeset.RakeSet, r map[string]any, reg *filter.FilterRegistry, timeout time.Duration) error {
	t, _ := r["type"].(string)

	switch t {
	case "ContextPattern":
		cp, err := rake.LoadContextPattern(r, reg, timeout)
		if err != nil {
			return err
		}
		return rs.Add(cp)

	case "FileMeta":
		// FileMeta configures no filters today, so it takes no registry.
		fm, err := rake.LoadFileMeta(r, timeout)
		if err != nil {
			return err
		}
		return rs.Add(fm)

	case "SimplePattern":
		p, err := rake.LoadPattern(r, reg, timeout)
		if err != nil {
			return err
		}
		return rs.Add(p)

	default:
		return fmt.Errorf("unsupported Rake type: %s", t)
	}
}

// buildFilterRegistry constructs the registry from the FilterRegistry section.
//
// The section is a list of single-key mappings:
//
//	- NamedFilter:
//	    - name: X
//	      type: regex
//	      ...
//	- FilterSet:
//	  - name: Y
//	  - filters: [ ... ]
//
// NamedFilter items are complete filter definitions plus a name. FilterSet
// items split the name and the filter list across separate entries, which are
// merged here.
func buildFilterRegistry(entries []map[string][]map[string]any, timeout time.Duration) (*filter.FilterRegistry, error) {
	reg := filter.NewFilterRegistry()

	for _, entry := range entries {
		if len(entry) != 1 {
			return nil, fmt.Errorf(
				"FilterRegistry entries must be single-key mappings (NamedFilter or FilterSet); got %d keys", len(entry))
		}

		for kind, items := range entry {
			switch kind {
			case "NamedFilter":
				for _, item := range items {
					name, ok := item["name"].(string)
					if !ok {
						return nil, fmt.Errorf("NamedFilter entry missing 'name'")
					}
					// Everything except the name is the filter definition.
					def := make(map[string]any, len(item))
					for k, v := range item {
						if k == "name" {
							continue
						}
						def[k] = v
					}
					f, err := filter.Load(def, timeout)
					if err != nil {
						return nil, fmt.Errorf("NamedFilter %q: %w", name, err)
					}
					if err := reg.RegisterNamed(name, f); err != nil {
						return nil, err
					}
				}

			case "FilterSet":
				merged := map[string]any{}
				for _, item := range items {
					for k, v := range item {
						merged[k] = v
					}
				}
				name, ok := merged["name"].(string)
				if !ok {
					return nil, fmt.Errorf("FilterSet entry missing 'name'")
				}
				raw, _ := merged["filters"].([]any)
				filters, err := reg.LoadList(raw, timeout)
				if err != nil {
					return nil, fmt.Errorf("FilterSet %q: %w", name, err)
				}
				if err := reg.RegisterSet(name, filters); err != nil {
					return nil, err
				}

			default:
				return nil, fmt.Errorf("unknown FilterRegistry entry kind: %q", kind)
			}
		}
	}

	return reg, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd golang && go test ./config/ -v`
Expected: PASS. `TestPasswordRakeReportsFullContextAndValue`,
`TestTokenRakeReportsNonEmptyValueAndBalancedContext` and
`TestSshpassRakeReportsPassword` are the three that fail against
uncorrected group numbers — if any fails, revisit Task 1 Step 2.

- [ ] **Step 6: Commit**

```bash
git add golang/config/
git commit -m "feat(golang): add config loading with dormant-section wiring

Builds the FilterRegistry before the rakes so filter references resolve,
and merges FilterSet name/filters entries as the shipped schema splits them.

DirectoryWalker.ExcludeSubdirs, ExcludeFileExtensions and Global.CommonTLDs
are now honored, defaulting to the previously-hardcoded Python values when
absent. An explicitly empty list means exclude nothing. IgnorePasswords,
IgnoreUsers and IgnoreHosts are parsed and reserved: they have no Python
counterpart, so wiring them would invent behavior.

The YAML rake tests assert the corrected group numbers produce the context
and value the README documents."
```

---

### Task 16: `cmd/datarake` — CLI flags and the goroutine pipeline

**Files:**
- Create: `golang/cmd/datarake/main.go`
- Test: `golang/cmd/datarake/main_test.go`

**Interfaces:**
- Consumes: everything.
- Produces: the `datarake` binary; `func parseCmdLine(argv []string) (*options, error)`; `func run(o *options) (int, error)`.

**Flag compatibility.** `pflag` shorthands must be a single character, so
argparse's `-dx`/`-dv` are registered as long flags and `argv` is preprocessed to
rewrite `-dx` to `--dx` and `-dv` to `--dv`. Without that, pflag reads `-dx` as
the grouped shorthands `-d -x` and errors.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"strings"
	"testing"
)

func TestParseDefaults(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.paths) != 1 || o.paths[0] != "." {
		t.Errorf("PATH must default to [.], got %#v", o.paths)
	}
	if o.format != "json" {
		t.Errorf("format must default to json, got %q", o.format)
	}
	if o.jobs <= 0 {
		t.Errorf("jobs must default to the CPU count, got %d", o.jobs)
	}
	if o.secure || o.quiet || o.summary || o.verbose || o.disableContext || o.disableValue {
		t.Errorf("boolean flags must default to false: %#v", o)
	}
}

func TestParseMultiplePaths(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "src", "lib"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.paths) != 2 || o.paths[0] != "src" || o.paths[1] != "lib" {
		t.Errorf("paths: %#v", o.paths)
	}
}

// argparse accepts flags after positionals; pflag must too.
func TestParseInterspersedFlags(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "src", "-v", "-f", "csv"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.verbose {
		t.Error("a flag after a positional must be parsed")
	}
	if o.format != "csv" {
		t.Errorf("format: got %q want csv", o.format)
	}
	if len(o.paths) != 1 || o.paths[0] != "src" {
		t.Errorf("paths: %#v", o.paths)
	}
}

func TestParseMultiCharShortFlags(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "-dx", "-dv"})
	if err != nil {
		t.Fatalf("-dx/-dv must be accepted for argparse compatibility: %v", err)
	}
	if !o.disableContext {
		t.Error("-dx must set disable-context")
	}
	if !o.disableValue {
		t.Error("-dv must set disable-value")
	}

	o2, err := parseCmdLine([]string{"datarake", "--disable-context", "--disable-value"})
	if err != nil {
		t.Fatal(err)
	}
	if !o2.disableContext || !o2.disableValue {
		t.Error("long forms must work too")
	}
}

func TestParseFormatChoices(t *testing.T) {
	for _, f := range []string{"csv", "json"} {
		if _, err := parseCmdLine([]string{"datarake", "-f", f}); err != nil {
			t.Errorf("format %q must be accepted: %v", f, err)
		}
	}
	// SARIF is dropped in the Go port.
	if _, err := parseCmdLine([]string{"datarake", "-f", "sarif"}); err == nil {
		t.Error("sarif must be rejected")
	}
	if _, err := parseCmdLine([]string{"datarake", "-f", "xml"}); err == nil {
		t.Error("an unknown format must be rejected")
	}
}

func TestParseEqualsForm(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "--format=csv", "--jobs=3"})
	if err != nil {
		t.Fatal(err)
	}
	if o.format != "csv" || o.jobs != 3 {
		t.Errorf("got format=%q jobs=%d", o.format, o.jobs)
	}
}

// A non-positive -j falls back to the CPU count, as in Python.
func TestParseNonPositiveJobsFallsBack(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "-j", "0"})
	if err != nil {
		t.Fatal(err)
	}
	if o.jobs <= 0 {
		t.Errorf("jobs must fall back to a positive value, got %d", o.jobs)
	}
}

func TestParseMatchTimeout(t *testing.T) {
	o, err := parseCmdLine([]string{"datarake", "--match-timeout", "250ms"})
	if err != nil {
		t.Fatal(err)
	}
	if o.matchTimeout.String() != "250ms" {
		t.Errorf("match timeout: got %v", o.matchTimeout)
	}
	def, _ := parseCmdLine([]string{"datarake"})
	if def.matchTimeout.String() != "1s" {
		t.Errorf("match timeout must default to 1s, got %v", def.matchTimeout)
	}
}

func TestUsageMentionsEveryFlag(t *testing.T) {
	usage := usageString()
	for _, f := range []string{
		"--format", "--output", "--secure", "--disable-context", "--disable-value",
		"--summary", "--quiet", "--verbose", "--jobs", "--config", "--match-timeout",
	} {
		if !strings.Contains(usage, f) {
			t.Errorf("usage must document %s:\n%s", f, usage)
		}
	}
	if strings.Contains(usage, "sarif") {
		t.Error("usage must not advertise sarif")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd golang && go test ./cmd/datarake/ -v`
Expected: FAIL — `undefined: parseCmdLine`, `undefined: usageString`.

- [ ] **Step 3: Write the implementation**

```go
// Command datarake scans a directory tree for secrets.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/spf13/pflag"

	datarake "github.com/jcwoods/datarake/golang"
	"github.com/jcwoods/datarake/golang/config"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/rakeset"
	"github.com/jcwoods/datarake/golang/walker"
	"github.com/jcwoods/datarake/golang/writer"
)

// version is injected via -ldflags -X main.version=...
var version = "dev"

type options struct {
	paths []string

	format string
	output string

	secure         bool
	disableContext bool
	disableValue   bool
	summary        bool
	quiet          bool
	verbose        bool

	jobs         int
	configPath   string
	matchTimeout time.Duration
}

// newFlagSet builds the flag set. Kept separate so usageString and
// parseCmdLine share one definition.
func newFlagSet(o *options) *pflag.FlagSet {
	fs := pflag.NewFlagSet("datarake", pflag.ContinueOnError)
	fs.SortFlags = false

	fs.StringVarP(&o.format, "format", "f", "json", "Output format (csv, json)")
	fs.StringVarP(&o.output, "output", "o", "", "Output location (defaults to stdout)")
	fs.BoolVarP(&o.secure, "secure", "s", false,
		"Enable secure output mode (no secrets displayed, secure context)")

	// argparse spells these -dx and -dv. pflag shorthands must be a single
	// character, so they are long flags here and argv is preprocessed.
	fs.BoolVar(&o.disableContext, "disable-context", false, "Disable output of context match")
	fs.BoolVar(&o.disableValue, "disable-value", false, "Disable output of secret matched")
	fs.BoolVar(&o.disableContext, "dx", false, "Alias for --disable-context")
	fs.BoolVar(&o.disableValue, "dv", false, "Alias for --disable-value")
	_ = fs.MarkHidden("dx")
	_ = fs.MarkHidden("dv")

	fs.BoolVarP(&o.summary, "summary", "u", false, "enable output of summary statistics")
	fs.BoolVarP(&o.quiet, "quiet", "q", false,
		"Do not output scan results, summary information only.")
	fs.BoolVarP(&o.verbose, "verbose", "v", false, "Enable verbose (diagnostic) output")
	fs.IntVarP(&o.jobs, "jobs", "j", 0,
		"Number of workers used to scan files (default: CPU count)")
	fs.StringVarP(&o.configPath, "config", "c", "",
		"Configuration file (defaults to the bundled datarake.yaml)")
	fs.DurationVar(&o.matchTimeout, "match-timeout", time.Second,
		"Per-line regex match timeout; regexp2 backtracks, so this bounds it")

	return fs
}

func usageString() string {
	var o options
	fs := newFlagSet(&o)
	return "usage: datarake [options] [PATH ...]\n\n" + fs.FlagUsages()
}

// normalizeArgs rewrites argparse's multi-character short flags into the long
// forms pflag understands. Without this, pflag reads -dx as -d -x.
func normalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "-dx":
			out = append(out, "--dx")
		case "-dv":
			out = append(out, "--dv")
		default:
			out = append(out, a)
		}
	}
	return out
}

func parseCmdLine(argv []string) (*options, error) {
	o := &options{}
	fs := newFlagSet(o)

	if err := fs.Parse(normalizeArgs(argv[1:])); err != nil {
		return nil, err
	}

	switch o.format {
	case "csv", "json":
	default:
		return nil, fmt.Errorf("invalid choice for --format: %q (choose from csv, json)", o.format)
	}

	o.paths = fs.Args()
	if len(o.paths) == 0 {
		o.paths = []string{"."}
	}

	if o.jobs <= 0 {
		o.jobs = runtime.NumCPU()
		if o.jobs < 1 {
			o.jobs = 1
		}
	}

	return o, nil
}

// job is one file's scan, in flight or complete.
type job struct {
	ctx      *walker.Context
	findings []*match.RakeMatch
	stats    rakeset.Stats
	err      error
	done     chan struct{}
}

func run(o *options) (int, error) {
	oc := match.NewOutputConfig(o.secure, o.disableContext, o.disableValue)

	var cfg *config.Config
	var err error
	if o.configPath == "" {
		cfg, err = config.Load(datarake.DefaultConfig, o.matchTimeout)
	} else {
		cfg, err = config.LoadFile(o.configPath, o.matchTimeout)
	}
	if err != nil {
		return 1, err
	}

	out := io.Writer(os.Stdout)
	if o.output != "" {
		f, err := os.Create(o.output)
		if err != nil {
			return 1, fmt.Errorf("open output %s: %w", o.output, err)
		}
		defer f.Close()
		out = f
	}

	wopts := writer.Opts{W: out, Quiet: o.quiet, Summary: o.summary, Output: oc}
	var w writer.DataRakeWriter
	if o.format == "csv" {
		w = writer.NewCSVWriter(wopts)
	} else {
		w = writer.NewJSONWriter(wopts)
	}

	if err := w.InitOutput(); err != nil {
		return 1, err
	}
	if err := w.InitSecrets(); err != nil {
		return 1, err
	}

	// Totals are owned solely by this goroutine.
	var totals rakeset.Stats

	// The main goroutine's only jobs are handing files to workers and writing
	// what they return. Workers scan but never write. In-flight scans are
	// bounded so a huge tree does not materialize every result at once.
	sem := make(chan struct{}, o.jobs)
	maxInFlight := o.jobs * 4
	if maxInFlight < o.jobs {
		maxInFlight = o.jobs
	}
	pending := make([]*job, 0, maxInFlight)

	// drainOne blocks on the oldest outstanding scan, preserving walk order,
	// and emits its results from this goroutine. A failure on one file is
	// logged and skipped rather than aborting the run.
	drainOne := func() error {
		j := pending[0]
		pending = pending[1:]
		<-j.done

		if j.err != nil {
			fmt.Fprintf(os.Stderr, "* ERROR scanning %s: %v\n", j.ctx.FullPath, j.err)
			return nil
		}
		for _, f := range j.findings {
			if err := w.WriteSecret(f); err != nil {
				return err
			}
		}
		totals.Add(j.stats)
		return nil
	}

	for _, root := range o.paths {
		dw := walker.New(root, cfg.Walker.ExcludeSubdirs, o.verbose)
		err := dw.Walk(func(c *walker.Context) error {
			j := &job{ctx: c, done: make(chan struct{})}

			sem <- struct{}{}
			go func(j *job) {
				defer func() { <-sem }()
				j.findings, j.stats, j.err = cfg.RakeSet.Scan(j.ctx)
				close(j.done)
			}(j)

			pending = append(pending, j)
			if len(pending) >= maxInFlight {
				return drainOne()
			}
			return nil
		})
		if err != nil {
			// Drain what is in flight before reporting, so no goroutine is
			// left blocked and partial results are still emitted.
			for len(pending) > 0 {
				if derr := drainOne(); derr != nil {
					return 1, derr
				}
			}
			fmt.Fprintf(os.Stderr, "* ERROR walking %s: %v\n", root, err)
		}
	}

	for len(pending) > 0 {
		if err := drainOne(); err != nil {
			return 1, err
		}
	}

	if err := w.EndSecrets(); err != nil {
		return 1, err
	}
	if err := w.InitSummary(); err != nil {
		return 1, err
	}
	if err := w.WriteSummary(writer.Summary{
		Files: totals.Files, Lines: totals.Lines,
		Hits: totals.Hits, Bytes: totals.Bytes,
	}); err != nil {
		return 1, err
	}
	if err := w.EndSummary(); err != nil {
		return 1, err
	}
	if err := w.EndOutput(); err != nil {
		return 1, err
	}

	return 0, nil
}

func main() {
	o, err := parseCmdLine(os.Args)
	if err != nil {
		if err == pflag.ErrHelp {
			fmt.Print(usageString())
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "datarake: %v\n\n%s", err, usageString())
		os.Exit(2)
	}

	code, err := run(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "datarake: %v\n", err)
	}
	os.Exit(code)
}
```

- [ ] **Step 4: Run test to verify it passes, and build**

Run: `cd golang && go test ./cmd/datarake/ -v && make build && ./bin/datarake --help`
Expected: tests PASS; the binary builds; `--help` lists every flag and no `sarif`.

- [ ] **Step 5: Smoke-test against the repository**

```bash
cd golang
printf 'username=jeffw\npassword=Sup3rSekrit!\n' > /tmp/dr-smoke/project.properties
mkdir -p /tmp/dr-smoke && printf 'username=jeffw\npassword=Sup3rSekrit!\n' > /tmp/dr-smoke/project.properties
./bin/datarake -f json -u /tmp/dr-smoke
```
Expected: one `password` finding whose `context.value` is
`password=Sup3rSekrit!` with offset 0 length 21, and `value.value` is
`Sup3rSekrit!` with offset 9 length 12 — the README's documented example,
which `master` reports with an empty context. Summary reports `"lines": 2`.

- [ ] **Step 6: Commit**

```bash
git add golang/cmd/datarake/
git commit -m "feat(golang): add CLI and the goroutine scan pipeline

One goroutine per file bounded by a semaphore, with the main goroutine
draining a FIFO oldest-first so output follows directory-walk order at any
-j. Only the main goroutine touches the writer.

argparse's -dx/-dv are preprocessed into long flags because pflag
shorthands must be single characters. --format drops sarif and gains
--match-timeout to bound regexp2 backtracking."
```

---

### Task 17: Golden-file end-to-end tests

**Files:**
- Create: `golang/e2e_test.go`, `golang/testdata/scan/*`, `golang/testdata/golden/*`
- Test: itself

**Interfaces:**
- Consumes: the built binary.
- Produces: golden fixtures; a regeneration flag `-update`.

- [ ] **Step 1: Create the fixture tree**

```bash
cd golang && mkdir -p testdata/scan/sub testdata/golden
cat > testdata/scan/app.properties <<'EOF'
username=jeffw
password=Sup3rSekrit!
EOF
cat > testdata/scan/sub/settings.yaml <<'EOF'
db:
  password: "yamlSekrit1"
EOF
cat > testdata/scan/sub/deploy.sh <<'EOF'
#!/bin/bash
wget https://jeff:superSekr3t@someremotehost.com?token=xyzzy.12345678
sshpass -psuperSekr3t jeff@somehost.com
EOF
cat > testdata/scan/id_rsa <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
notarealkey
-----END RSA PRIVATE KEY-----
EOF
cat > testdata/scan/README.md <<'EOF'
Nothing sensitive here.
EOF
printf 'password=caf\xc3\xa9Sekrit1\n' > testdata/scan/utf8.properties
```

The `utf8.properties` fixture exists specifically to pin rune-based offsets: a
byte-offset implementation reports a different `value.offset` for that line.

- [ ] **Step 2: Write the failing test**

```go
package datarake_test

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate golden files")

var binary string

func TestMain(m *testing.M) {
	flag.Parse()

	dir, err := os.MkdirTemp("", "datarake-e2e")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binary = filepath.Join(dir, "datarake")
	build := exec.Command("go", "build", "-o", binary, "./cmd/datarake")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

// runScan executes the binary and returns stdout with the scan root's absolute
// path normalized away.
func runScan(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(binary, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %v: %v\nstderr: %s", args, err, errb.String())
	}
	return out.String()
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run: go test ./ -update): %v", path, err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s\n got: %s\nwant: %s", path, got, want)
	}
}

func TestGoldenJSON(t *testing.T) {
	got := runScan(t, "-f", "json", "-u", "testdata/scan")
	checkGolden(t, "scan.json", got)
}

func TestGoldenCSV(t *testing.T) {
	got := runScan(t, "-f", "csv", "-u", "testdata/scan")
	checkGolden(t, "scan.csv", got)
}

func TestGoldenSecureJSON(t *testing.T) {
	got := runScan(t, "-f", "json", "-s", "testdata/scan")
	checkGolden(t, "scan-secure.json", got)
	if strings.Contains(got, "Sup3rSekrit!") {
		t.Error("secure mode leaked a secret")
	}
}

// The output must not depend on the worker count.
func TestOutputIsIdenticalAcrossJobCounts(t *testing.T) {
	base := runScan(t, "-f", "json", "-u", "-j", "1", "testdata/scan")
	for _, j := range []string{"2", "4", "8", "16"} {
		got := runScan(t, "-f", "json", "-u", "-j", j, "testdata/scan")
		if got != base {
			t.Errorf("-j %s output differs from -j 1\n got: %s\nwant: %s", j, got, base)
		}
	}
}

// Pins rune offsets: a byte-offset implementation reports a different offset.
func TestNonASCIILineUsesRuneOffsets(t *testing.T) {
	got := runScan(t, "-f", "json", "testdata/scan")
	if !strings.Contains(got, `"utf8.properties"`) {
		t.Fatalf("expected a finding in utf8.properties:\n%s", got)
	}
	// "password=" is 9 runes, so the value starts at rune 9 even though the
	// line contains a two-byte character later on.
	if !strings.Contains(got, `"offset": 9`) {
		t.Errorf("expected a rune offset of 9:\n%s", got)
	}
}

func TestSshpassReportsNonEmptyValue(t *testing.T) {
	got := runScan(t, "-f", "json", "testdata/scan")
	if !strings.Contains(got, "superSekr3t") {
		t.Errorf("sshpass and auth url must report a non-empty value; master reports \"\":\n%s", got)
	}
}

func TestContextsAreNeverEmpty(t *testing.T) {
	got := runScan(t, "-f", "json", "testdata/scan")
	if strings.Contains(got, `"context": {"value": "", "offset": 0, "length": 0}`) {
		t.Errorf("no finding may carry an empty context; that is the master bug:\n%s", got)
	}
}

func TestQuietWithSummaryEmitsOnlySummary(t *testing.T) {
	got := runScan(t, "-f", "json", "-q", "-u", "testdata/scan")
	if strings.Contains(got, `"secrets"`) {
		t.Errorf("quiet must omit the secrets key: %s", got)
	}
	if !strings.Contains(got, `"summary"`) {
		t.Errorf("summary must be present: %s", got)
	}
}

func TestOutputToFile(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out.json")
	runScan(t, "-f", "json", "-o", dst, "testdata/scan")
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"secrets"`)) {
		t.Errorf("-o must write the document to the file: %s", b)
	}
}

func TestExcludedExtensionIsSkipped(t *testing.T) {
	// README.md has no findings, and the default blacklist excludes .css etc.
	got := runScan(t, "-f", "json", "testdata/scan")
	if strings.Contains(got, "README.md") {
		t.Errorf("README.md must produce no findings: %s", got)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd golang && go test . -run Golden -v`
Expected: FAIL — golden files do not exist yet.

- [ ] **Step 4: Generate and review the goldens**

```bash
cd golang && go test . -update
```

Now **read each golden file** and confirm by eye:
- every `context.value` is non-empty and looks like real source text
- the `password` finding in `app.properties` reports context
  `password=Sup3rSekrit!` offset 0 length 21, value `Sup3rSekrit!` offset 9 length 12
- `deploy.sh` yields an `auth url` finding whose value is `superSekr3t`, and an
  `sshpass` finding whose value is `superSekr3t`
- `id_rsa` yields both a `ssh identity file` filemeta finding with `"line": null`
  and a `private key` content finding
- `utf8.properties` reports `"offset": 9` for its value
- the summary line count equals the real number of lines

If any of these is wrong, the bug is in the corresponding earlier task — fix it
there and regenerate rather than accepting a wrong golden.

- [ ] **Step 5: Run the full suite**

Run: `cd golang && make test && make race && make lint`
Expected: all PASS, no races, no vet or gofmt complaints.

- [ ] **Step 6: Commit**

```bash
git add golang/e2e_test.go golang/testdata/
git commit -m "test(golang): add golden-file end-to-end tests

Runs the built binary over a fixture tree and compares complete JSON and
CSV documents. Asserts output is byte-identical across -j 1 through 16,
pinning the walk-order guarantee, and that no finding carries an empty
context -- the defect this port corrects.

utf8.properties exists to pin rune-based offsets: a byte-offset
implementation reports a different value.offset for that line."
```

---

### Task 18: `golang/README.md` and root build integration

**Files:**
- Create: `golang/README.md`
- Modify: `Makefile` (add a `golang` target), `.gitignore` (ignore `golang/bin/`)

**Interfaces:**
- Consumes: the finished port.
- Produces: documentation.

- [ ] **Step 1: Write `golang/README.md`**

Include, with no placeholders:
- build and test instructions (`make`, `make test`, `make race`, `make cross`)
- the full flag list, matching `usageString()`
- a "Differences from the Python implementation" section reproducing the
  spec's delta table verbatim: no SARIF, no `entropy.py`, corrected contexts and
  values, true line counts, honored `DirectoryWalker`/`CommonTLDs` sections,
  `.svn` no longer pruned and `.xyz` no longer valid under the shipped config,
  encoding guesses may differ on non-UTF-8 input, the regex match timeout,
  `relPath` hardening, dead code omitted, and sorted traversal order
- a note that `Global.IgnorePasswords`, `IgnoreUsers`, `IgnoreHosts` and
  `skipcontexts` are parsed but reserved, and why
- a note that `regexp2` is used rather than RE2, with the backtracking caveat
  and the `--match-timeout` mitigation

- [ ] **Step 2: Add the root Makefile target**

```makefile
.PHONY: golang
golang:
	$(MAKE) -C golang all

.PHONY: golang-test
golang-test:
	$(MAKE) -C golang test
```

- [ ] **Step 3: Update `.gitignore`**

Append:

```
golang/bin/
```

- [ ] **Step 4: Verify**

Run: `make golang && make golang-test && ./golang/bin/datarake --help`
Expected: builds and tests from the repository root; help text prints.

- [ ] **Step 5: Verify the README's claims against the binary**

Run each command the README shows and confirm the described output. A README
that documents behavior the binary does not have is the same class of defect as
the empty-context bug this port fixes — the Python README already documents a
context that `master` does not produce.

- [ ] **Step 6: Commit**

```bash
git add golang/README.md Makefile .gitignore
git commit -m "docs(golang): add README and root build integration

Documents every intentional behavior difference from the Python
implementation, including the reserved config keys and the regexp2
backtracking caveat."
```

---

## Plan Self-Review

**Spec coverage.** Every spec section maps to a task:

| Spec section | Task |
|---|---|
| Goals 1–5 | 1–18 |
| Non-goals (SARIF, entropy.py) | Global Constraints; verified in 16 (`-f sarif` rejected) |
| Decision 1 (regexp2 + MatchTimeout) | 1, 7, 16 |
| Decision 2 (group corrections) | 1 (config), 15 (assertions), 17 (golden) |
| Decision 3 (line count) | 12 |
| Decision 4 (dormant sections) | 15 |
| Decision 5 (full test port) | every task; 15 (YAML rakes), 17 (golden) |
| Why not one module per class | 2 (`RakeInfo`) |
| File layout / class mapping | File Structure table; 2–14 |
| Virtual dispatch | 7 (`SetSelf`), 10, 11 |
| Concurrency | 12 (`Scan` contract), 16 (pipeline), 17 (`-j` invariance) |
| Output configuration | 2 (`OutputConfig`) |
| Config brace shorthand | 1 |
| Config group numbers | 1 |
| Config pattern corrections | 1 |
| Dormant config sections | 15 |
| Line reading / universal newlines | 12 |
| Encoding detection | 12 |
| JSON output (3 differences) | 14 |
| CSV output | 13 |
| CLI (pflag) | 16 |
| Hardening (`relPath`, dead code) | 6, and omissions noted in 2 |
| Testing (3 layers) | all; 15; 17 |
| Makefile | 1 |
| Fidelity deltas 1–11 | 18 (documented), enforced in origin tasks |

No gaps.

**Type consistency.** Checked across tasks: `match.RakeInfo` (2) is satisfied by
`rake.Rake`'s `PType`/`PDesc`/`Severity` (6). `filter.RakeFilter` (3) is consumed
by `Pattern.AddFilter` (7) and `FilterRegistry.LoadList` (4). `rake.ContentRake`
and `rake.MetaRake` (6) are satisfied by `Pattern` (7), `ContextPattern` (9),
`FileMeta` (8) and consumed by `RakeSet.Add` (12). `rakeset.Stats` (12) feeds
`writer.Summary` (13) via explicit field copies in `run` (16). `match.OutputConfig`
(2) threads through `Opts` (13) into both writers (13, 14).

**Amendment — shared plain `OutputConfig`.** Tasks 3 and 10 each define a local
`plainOutput`/`plainOutputConfig` closure so filters can read a match's raw
value. That is duplicated and awkward. Implement it once instead, in Task 2's
`match/rakematch.go`:

```go
// PlainOutput is a non-secure, nothing-disabled configuration used when a
// filter needs to inspect a match's real value. Filtering runs before output
// is configured, and a filter must see the actual secret to judge it.
// Safe to share: OutputConfig is immutable.
var PlainOutput = NewOutputConfig(false, false, false)
```

Then in Task 3 delete the `plainOutput` closure from `regexfilter.go` and use
`match.PlainOutput` in both `literalfilter.go` and `regexfilter.go`; in Task 10
delete the `plainOutputConfig` closure from `rake.go` and use `match.PlainOutput`
in `rakehostname.go`, `rakeemail.go`, `rakebasicauth.go` and `rakejwtauth.go`
(replacing the `plainOutputConfig()` call sites). Add to Task 2's tests:

```go
func TestPlainOutputExposesValueAndContext(t *testing.T) {
	m := New(fakeRake{"t", "d", "LOW"}, "f", intp(1))
	m.SetValue("hunter2", 0, -1)
	if v := m.Value(PlainOutput); v == nil || *v != "hunter2" {
		t.Errorf("PlainOutput must expose the real value, got %v", v)
	}
}
```

**Placeholder scan.** One defect found and corrected: Task 16 Step 5 had a
`printf` redirect into `/tmp/dr-smoke/` before the `mkdir -p`. The corrected
order is:

```bash
mkdir -p /tmp/dr-smoke
printf 'username=jeffw\npassword=Sup3rSekrit!\n' > /tmp/dr-smoke/project.properties
./bin/datarake -f json -u /tmp/dr-smoke
```

A second: Task 12's test file defines `ctxFor` with an unused variable in the
extension loop (`if i := len(name) - 1; i >= 0`). Replace that block with:

```go
	ext, has := "", false
	for j := len(name) - 1; j >= 0; j-- {
		if name[j] == '.' {
			ext, has = name[j+1:], true
			break
		}
	}
```

A third: Task 15's `yamlrakes_test.go` calls `ctx(name, ext, 1)` and
`ctx("README.md", "md")`. Declare it variadic as noted in that task:

```go
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
```

A fourth: Task 10's `TestIsValidHostname` builds `long` with a loop; use
`strings.Repeat("a", 64)` and import `strings`.

A fifth: Task 12's `RakeSet.Add` type switch is redundant — a `ContentRake` and a
`MetaRake` have disjoint method sets (`Match`/`Filter` versus `MatchContext`), so
the trailing re-check is dead. Simplify to a two-case switch with a default
error, and keep the `Part()` guard.
