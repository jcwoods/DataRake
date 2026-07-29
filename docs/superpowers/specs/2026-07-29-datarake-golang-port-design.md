# DataRake Go Port — Design

**Date:** 2026-07-29
**Status:** Approved design, pending implementation plan
**Scope:** Port the `master` branch of datarake from Python to Go, in `./golang`.

## Goals

1. Port datarake to Go, one file per Python class, grouped into cohesive packages.
2. Preserve the `datarake.yaml` configuration *syntax* exactly.
3. Replace `concurrent.futures.ThreadPoolExecutor` parallelism with goroutines.
4. Preserve the JSON and CSV output formats.
5. Ship a `Makefile` driving build, test, and lint.

## Non-goals

- **SARIF output is dropped.** `DataRakeSARIFWriter` is not ported; `-f/--format`
  accepts only `csv` and `json`.
- **`entropy.py` is not ported.** All 401 lines and 4 classes (`EntropyParser`,
  `HexEntropyParser`, `B64EntropyParser`, `TxtEntropyParser`) are unreachable from
  the CLI and from the test suite — nothing imports the module. It stays
  Python-only.
- No new rake types, no new config keys, no new output formats.
- The Python implementation is left untouched. This is an additive `./golang` tree.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Regex engine: `github.com/dlclark/regexp2` | The shipped config needs backreferences (10 patterns) and Python conditional groups (2 patterns). Neither is expressible in RE2 — it is a finite-automaton limitation, not an implementation gap. |
| 2 | Correct the rake group numbers from the first commit | `master` emits empty contexts for every content finding and empty values for `token` and `sshpass` findings. Shipping that faithfully would ship a scanner whose human-review field is always blank. |
| 3 | Fix the summary line count off-by-one | Consistent with #2: the port ships correct rather than bug-compatible. |
| 4 | Wire up the dormant `Global:` and `DirectoryWalker:` config sections | They already describe intent; today they are parsed by nobody. See "Dormant config" for the one part that stays inert. |
| 5 | Port the full test suite (~90 tests), table-driven, plus golden-file end-to-end tests | With byte-diff against Python off the table (#2, #3), tests are the fidelity net. |

### On decision #1

`regexp2` is a backtracking engine, so catastrophic backtracking is reachable from
a crafted input line — and this tool is pointed at untrusted repositories. This
was raised and the choice was reaffirmed. Mitigation: every compiled pattern gets
a `regexp2.Regexp.MatchTimeout`, configurable via `--match-timeout` (default
`1s`). A timeout is reported to stderr and the line is skipped, matching the
existing per-file error-and-continue posture.

`regexp2` also turns out to be a *better* fidelity match than stdlib `regexp`:
it indexes in **runes**, not bytes, matching Python's character offsets exactly.
Verified on `"héllo 日本 password=Sup3rSekrit!"` — Python and `regexp2` both
report offset 18; stdlib `regexp` reports byte offset 23. Since `RakeMatch`
documents offsets as "measured in characters, not bytes", and non-UTF-8 input is
exactly what the `chardet` support exists to handle, this preserves the
`offset`/`length` fields for free.

## Architecture

### Why not one Go module per class

Go's `module` is a `go.mod` versioning unit; 18 of them would be unworkable. It
is also impossible here: `RakeMatch.__init__` reads `rake.ptype`/`pdesc`/`severity`
while `Rake.filter` takes a `RakeMatch`. Python resolves this with the forward
declaration at `common.py:13`; Go rejects import cycles at compile time.

Resolution: **one file per class**, grouped into packages, with the cycle broken by
an interface. `match` declares what it needs from a rake and never imports `rake`:

```go
// match/rakematch.go
type RakeInfo interface {
    PType() string
    PDesc() string
    Severity() string
}
```

Dependency flow is then acyclic: `match ← filter ← rake ← rakeset ← config ← cmd`.

### File layout

```
golang/
├── Makefile
├── go.mod                          module github.com/jcwoods/datarake/golang
├── go.sum
├── datarake.yaml                   corrected copy of datarake/datarake.yaml
├── match/
│   └── rakematch.go                RakeMatch, RakeInfo, OutputConfig
├── filter/
│   ├── rakefilter.go               RakeFilter
│   ├── literalfilter.go            RakeLiteralFilter
│   ├── regexfilter.go              RakeRegexFilter
│   └── filterregistry.go           FilterRegistry
├── rake/
│   ├── rake.go                     Rake
│   ├── rakefilemeta.go             RakeFileMeta
│   ├── rakepattern.go              RakePattern
│   ├── rakecontextpattern.go       RakeContextPattern
│   ├── rakehostname.go             RakeHostname
│   ├── rakeemail.go                RakeEmail
│   ├── rakebasicauth.go            RakeBasicAuth
│   └── rakejwtauth.go              RakeJWTAuth
├── rakeset/
│   └── rakeset.go                  RakeSet
├── walker/
│   └── directorywalker.go          DirectoryWalker
├── writer/
│   ├── datarakewriter.go           DataRakeWriter
│   ├── csvwriter.go                DataRakeCSVWriter
│   └── jsonwriter.go               DataRakeJSONWriter
├── config/
│   └── config.go                   loadConfig, filter registry, Global/DirectoryWalker
└── cmd/datarake/
    └── main.go                     parseCmdLine, main, scan pipeline
```

### Class mapping

19 Python classes, minus `DataRakeSARIFWriter`, equals 18 files.

| Python class | Source | Go file | Go type |
|---|---|---|---|
| `DirectoryWalker` | common.py:16 | `walker/directorywalker.go` | `DirectoryWalker` |
| `Rake` | common.py:88 | `rake/rake.go` | `Rake` |
| `RakeMatch` | common.py:149 | `match/rakematch.go` | `RakeMatch` |
| `RakeSet` | common.py:417 | `rakeset/rakeset.go` | `RakeSet` |
| `RakeFilter` | common.py:621 | `filter/rakefilter.go` | `RakeFilter` (interface) |
| `FilterRegistry` | common.py:655 | `filter/filterregistry.go` | `FilterRegistry` |
| `RakeLiteralFilter` | common.py:734 | `filter/literalfilter.go` | `LiteralFilter` |
| `RakeRegexFilter` | common.py:786 | `filter/regexfilter.go` | `RegexFilter` |
| `RakeFileMeta` | rakes.py:11 | `rake/rakefilemeta.go` | `FileMeta` |
| `RakePattern` | rakes.py:99 | `rake/rakepattern.go` | `Pattern` |
| `RakeContextPattern` | rakes.py:236 | `rake/rakecontextpattern.go` | `ContextPattern` |
| `RakeHostname` | rakes.py:326 | `rake/rakehostname.go` | `Hostname` |
| `RakeEmail` | rakes.py:400 | `rake/rakeemail.go` | `Email` |
| `RakeBasicAuth` | rakes.py:438 | `rake/rakebasicauth.go` | `BasicAuth` |
| `RakeJWTAuth` | rakes.py:472 | `rake/rakejwtauth.go` | `JWTAuth` |
| `DataRakeWriter` | __main__.py:22 | `writer/datarakewriter.go` | `DataRakeWriter` (interface) |
| `DataRakeCSVWriter` | __main__.py:60 | `writer/csvwriter.go` | `CSVWriter` |
| `DataRakeJSONWriter` | __main__.py:105 | `writer/jsonwriter.go` | `JSONWriter` |
| `DataRakeSARIFWriter` | __main__.py:163 | — | **dropped** |

Module-level functions from `__main__.py` (`parseCmdLine`, `_buildFilterRegistry`,
`loadConfig`, `main`) go to `cmd/datarake/main.go` and `config/config.go`.
`_default_config_text` becomes a `go:embed` of `golang/datarake.yaml`, replacing
the `importlib.resources` lookup.

### Virtual dispatch for `filter()`

`RakePattern.match` calls `self.filter(...)`, and `RakeHostname`, `RakeEmail`,
`RakeBasicAuth`, `RakeJWTAuth` each override `filter` and chain to
`super().filter(m)`. Go embedding gives no virtual dispatch, so each subclass
constructor installs a back-reference:

```go
type Filterer interface{ Filter(*match.RakeMatch) bool }

type Pattern struct {
    Rake
    filters []filter.RakeFilter
    self    Filterer      // outermost override; defaults to the Pattern itself
}

func (p *Pattern) Match(ctx *walker.Context, text string) []*match.RakeMatch {
    // ... p.self.Filter(rm) reproduces Python's dynamic dispatch
}

func NewHostname(domain string) *Hostname {
    h := &Hostname{...}
    h.self = h            // Pattern.Match now routes through Hostname.Filter
    return h
}
```

`Hostname.Filter` performs its `isValidHostname` check then calls
`h.Pattern.Filter(m)`, mirroring the `super()` chain.

Note the existing double-filter behavior: `RakePattern.match` filters internally
*and* `RakeSet.match_content` calls `rake.filter(m)` again (`common.py:466`).
Filters are pure and idempotent, so this only costs work. Preserved as-is to
avoid changing which matches survive.

### Concurrency

Python hands files to a `ThreadPoolExecutor`, bounds in-flight work with a
`deque`, and drains oldest-first so output follows directory-walk order — a
guarantee the README states explicitly. The Go version keeps that structure:

```go
type job struct {
    ctx      *walker.Context
    findings []*match.RakeMatch
    stats    rakeset.Stats
    err      error
    done     chan struct{}
}

sem := make(chan struct{}, jobs)          // caps concurrent scans
maxInFlight := max(jobs*4, jobs)          // == Python's max_in_flight
pending := make([]*job, 0, maxInFlight)

for _, root := range paths {
    for ctx := range walker.New(root, verbose).Walk() {
        j := &job{ctx: ctx, done: make(chan struct{})}
        sem <- struct{}{}
        go func(j *job) {
            defer func() { <-sem }()
            j.findings, j.stats, j.err = rs.Scan(j.ctx)
            close(j.done)
        }(j)
        pending = append(pending, j)
        if len(pending) >= maxInFlight {
            drainOne(&pending)            // blocks on <-j.done, emits, accumulates
        }
    }
}
for len(pending) > 0 { drainOne(&pending) }
```

Invariants, matching Python:

- **Only the main goroutine touches the writer.** Workers compute and return; they
  never emit. No output interleaving, deterministic order at any `-j`.
- `RakeSet.Scan` mutates no shared state. Each `Context` is created by the walker
  and owned solely by its scanning goroutine.
- Totals are owned by the main goroutine.
- A scan error is printed to stderr as `* ERROR scanning <path>: <err>` and that
  file is skipped, matching `__main__.py:432`.

One goroutine per file is cheap; `sem` bounds actual concurrency, so this is
equivalent to a worker pool without needing one.

### Output configuration

`RakeMatch` carries four mutable class-level globals (`_secure`,
`_disable_context`, `_disable_value`, `_has_been_read`) plus a mutated `fields`
`OrderedDict`. `_has_been_read` is written on *every* attribute read, which under
Go's race detector is a straightforward data race across scanning goroutines.

Replacement: an immutable `match.OutputConfig`, built once in `main` from the
flags and passed to the writer and to `AsList`/`AsDict`. The `_has_been_read`
guard is deleted — it only ever raised errors on API misuse, and the new
structure makes that misuse unrepresentable. **Output is unaffected.**

The three mutators must be applied in the same order as `main` applies them
(`secure`, then `disable_context`, then `disable_value`) because they overlap:
`set_secure` sets `fields['context'] = True`, which a later `disable_context`
flips back to `False`. `OutputConfig` computes the final ordered field set by
applying them in that order.

Field order for the CSV header and `AsList`, from `common.py:157`:
`file, line, label, severity, description, key_offset, key_length, key,
value_offset, value_length, value, context_offset, context_length, context`,
with `key_offset`, `key_length`, `key` disabled by default.

## Configuration file

`golang/datarake.yaml` is a copy of `datarake/datarake.yaml`. **The syntax and
schema are unchanged** — same keys, same nesting, same `FilterRegistry` shape.
Three classes of edit to the *values*:

### 1. Brace shorthand — required by the engine

Python reads `{,32}` as `{0,32}`. .NET semantics, which `regexp2` implements,
treat it as a **literal**. Verified: `^.{,5}$` matches the 5-character string
`a{,5}` and fails to match `abc`.

| Location | Change |
|---|---|
| token / c-family pattern | `[a-z0-9_]{,32}` → `{0,32}` |
| password / c-family pattern | `\S{,32}` → `{0,32}` |
| password / js-ts-py pattern | `\S{,32}` → `{0,32}` |
| password / yaml pattern | `\S{,32}` → `{0,32}` |
| password / json pattern | `\S{,32}` → `{0,32}` |
| password / null-context filter | `^.{,5}$` → `^.{0,5}$` |

### 2. Group-number corrections

`RakePattern.match` maps config group *k* to regex group *k+1* (`rakes.py:151`),
because config numbers index 0-based into a `findall` tuple that omits group 0.
That convention is correct for `auth url`, `auth token`, `private key`, the four
`sensitive environment variable` contexts, `RakeHostname`, and `RakeEmail` — all
verified group-by-group. It is wrong for three rakes:

| Rake | contextgroup | keygroup | valgroup |
|---|---|---|---|
| token / null context | 1 → **0** | 3 → **2** | 7 → **6** |
| token / c-family | 1 → **0** | 2 → **1** | 3 (correct) |
| token / js-ts-py | 1 → **0** | 2 → **1** | 4 (correct) |
| password / null context | 1 → **0** | 3 → **2** | 7 (correct) |
| sshpass | 0 (unchanged) | — | 2 (unchanged) |

`sshpass` keeps both numbers; they only become *meaningful* once its pattern gains
an outer capture group under "Pattern corrections" below.

Evidence, from the real config pattern against `authtoken="s3kr3tvalue"`:

```
g1 = 'authtoken="s3kr3tvalue'   <- the intended context
g2 = ''                          <- contextgroup 1 lands here
g3 = 'authtoken'                 <- the intended key
g4 = 'en'                        <- keygroup 3 lands here
g7 = 's3kr3tvalue'               <- the intended value
g8 = ''                          <- valgroup 7 lands here: a backref echo group
```

### 3. Pattern corrections

Two patterns cannot be fixed by renumbering alone:

**`sshpass`** has no capture group spanning the whole match, so `contextgroup`
has nothing valid to point at, and `valgroup: 2` lands on the backreference echo.
Add an outer group and renumber the backreference:

```
-  '\bsshpass .*-p\s?([\'"]?)(\S+)(\1)'
+  '\b(sshpass .*-p\s?([\'"]?)(\S+)(\2))'
```

Verified: `g1 = 'sshpass -psuperSekr3t'`, `g3 = 'superSekr3t'`, so
`contextgroup: 0` and `valgroup: 2` both become correct with no further edit.
`tests/test1.sh` exercises this rake and currently reports an empty value.

**`token` / null context** ends in `(\5)`, which echoes group 5 — itself the
backreference to the *key* quote — rather than closing the *value* quote. The
context therefore ends mid-string with an unbalanced quote:

```
-  ...([\x21\x23-\x26\x28-\x7e]{6,})(\5))
+  ...([\x21\x23-\x26\x28-\x7e]{6,})(\6))
```

Verified: context becomes `authtoken="s3kr3tvalue"` (balanced), and an unquoted
`authtoken=s3kr3tvalue` still matches, since group 6 captures the empty string.

### Dormant config sections

Today `loadConfig` reads only `verbose`, `FilterRegistry`, and `Rakes`. The
`Global:` and `DirectoryWalker:` sections are parsed by nobody, while equivalent
values sit hardcoded in the Python. Three of the five keys have a hardcoded
counterpart and are wired up:

| Config key | Hardcoded counterpart | Go behavior |
|---|---|---|
| `DirectoryWalker.ExcludeSubdirs` | `DirectoryWalker.__init__` → `['.svn', '.git']` | Honored; that list is the default when the key is absent |
| `DirectoryWalker.ExcludeFileExtensions` | `RakeSet.DEFAULT_BLACKLIST` | Honored; `DEFAULT_BLACKLIST` is the default when absent |
| `Global.CommonTLDs` | `RakeHostname.TLDs` | Honored by `NewHostname`/`NewEmail`; `TLDs` is the default when absent |

**`CommonTLDs` does not affect CLI scans.** Only `ContextPattern`, `FileMeta`,
and `SimplePattern` are constructible from YAML (`__main__.py:363-365`).
`RakeHostname` and `RakeEmail` — the only consumers of the TLD list — are
library-only API, exported from `__init__.py` and exercised by the test suite but
never instantiated by `loadConfig`. Honoring `CommonTLDs` therefore changes
behavior for library consumers and tests only. Wiring it into the scan path would
require a new YAML rake type, which is out of scope.

Two consequences of honoring the shipped config, both intended:

- `ExcludeSubdirs: ['.git', '__pycache__']` **replaces** the hardcoded default, so
  `.svn` is no longer pruned. Add `.svn` to the config to keep it.
- `CommonTLDs` in the config has 18 entries; `RakeHostname.TLDs` has 19 — the
  config omits `xyz`. Hostnames ending in `.xyz` therefore stop validating unless
  `xyz` is added to the config.

`ExcludeFileExtensions` entries carry no leading dot (`'doc'`) while
`DEFAULT_BLACKLIST` entries do (`'.doc'`). Both are normalized to a dotted suffix
and matched case-insensitively against the end of the filename, preserving the
existing suffix semantics at `common.py:540` — which is what makes multi-part
entries like `.tar.gz` work.

**`Global.IgnorePasswords`, `Global.IgnoreUsers`, `Global.IgnoreHosts`, and the
`token` rake's `skipcontexts:` key stay inert.** Unlike the three above, these
have *no* hardcoded counterpart anywhere in
the Python — no code path consumes them or anything equivalent. (`Rake.common_usernames`
and `Rake.common_passwords` are different lists and are themselves unused.
`skipcontexts` appears only on the `token` rake and is read by no code —
`RakeContextPattern.load` reads `name`, `description`, `severity`, and `contexts`
only.) Wiring any of them up would mean inventing suppression semantics that have
never existed, which is a feature, not a port. They are parsed into the config
struct and documented as reserved.

## Implementation notes

### Line reading

Python opens files in text mode, so universal-newline translation applies: `\r\n`
and lone `\r` both become `\n`, and each yielded line retains its trailing `\n`.
That trailing newline is load-bearing — `RakeBasicAuth` and `private key` anchor
with `$`. Go needs a `universalNewlineReader` wrapping `bufio.Reader` to
reproduce both the translation and the retained terminator.

`regexp2` matches Python here: `$` matches at end of input or immediately before a
final `\n`. Verified against `"Authorization: Basic dXNlcjpwYXNzd29yZAo=\n"`.

### Encoding detection

`chardet.detect` on the first 2048 bytes becomes `saintfish/chardet`, with
decoding via `x/text/encoding/ianaindex` and `transform.Reader`. Unknown or
inconclusive results fall back to UTF-8, as at `common.py:557`. A decode error
mid-file aborts that file with `lines = 0`, matching the `UnicodeDecodeError`
handler.

**Fidelity caveat:** Go's chardet is a different detector than Python's, so the
*guessed* encoding may differ on non-UTF-8 input. UTF-8 and ASCII — all test
fixtures and the overwhelming majority of real input — are unaffected.

### JSON output

Matching `json.dumps` output requires three deliberate choices, because Go's
`encoding/json` differs from Python's defaults in all three:

1. **Separators.** Python emits `", "` and `": "`; Go emits `,` and `:`. Objects
   and arrays are assembled explicitly with Python's spacing.
2. **Non-ASCII.** Python defaults to `ensure_ascii=True`, escaping non-ASCII as
   `\uXXXX` with surrogate pairs for astral characters. Go emits raw UTF-8. A
   `jsonEscape` helper reproduces Python's behavior.
3. **HTML characters.** Go escapes `<`, `>`, and `&` into their `\uXXXX` forms
   (`003c`, `003e`, `0026`); Python leaves them literal. The explicit escaper
   leaves them literal.

Verified against both implementations, showing all three differences at once:

```
input: {'path': 'héllo/日本.txt', 'context': 'a<b>c&d'}

py:    {"path": "h\u00e9llo/\u65e5\u672c.txt", "context": "a<b>c&d"}
go:    {"path":"héllo/日本.txt","context":"a\u003cb\u003ec\u0026d"}
```

Key order is Python dict insertion order — `path, line, type, description,
severity, context, value` (`common.py:396`) — so `AsDict` is emitted field by
field, not via map marshaling. Inner `value`/`offset`/`length` fields must be
able to emit `null`, so they are pointer-typed.

### CSV output

`csv.writer` defaults to `\r\n` line terminators and `QUOTE_MINIMAL`. Go's
`encoding/csv` defaults to `\n` and additionally quotes any field with **leading
whitespace**, which Python does not. Since a context can legitimately begin with a
space, the port uses a small Python-compatible writer: `\r\n` terminators, and
quoting only when the field contains a delimiter, a quote, `\r`, or `\n`. `nil`
renders as the empty field, as Python renders `None`.

### CLI

`spf13/pflag` rather than stdlib `flag`: Go's `flag` stops parsing at the first
positional, so `datarake . -v` — accepted by argparse — would silently drop `-v`.
pflag also supports both `-f csv` and `--format=csv`.

Flags are unchanged from the Python except `-f/--format`, which loses `sarif`
(passing it is a usage error), and the new `--match-timeout`. `-h/--help` output
should read as closely to the argparse text as pflag allows.

The `verbose` split is preserved as-is: the config's `verbose:` key drives
`RakeSet`, while `-v` drives `DirectoryWalker` (`__main__.py:360` vs `442`).

### Hardening

`Rake.relPath` does `while relpath[0] == '/'`, which raises `IndexError` when
`fullpath == basepath`. The Go version guards the empty case instead of panicking.
Reachable only when a scan target is a file rather than a directory.

`RakeMatch.external_id` is not ported. Nothing calls it, and its own comment says
`TODO - check that this is not being used!`. `Rake.common_usernames` and
`common_passwords` are likewise unused and not ported.

## Testing

`make test` runs everything. Three layers:

1. **Ported unit tests** — all ~90 tests from `tests/test_rakes.py`, converted to
   Go table-driven tests, colocated with the code under test
   (`rake/rakepattern_test.go`, `filter/regexfilter_test.go`, …).
2. **YAML rake tests** — the `_YAMLRakesMixin` cases, loading the real
   `golang/datarake.yaml`. These are what prove the group-number and pattern
   corrections are right. Each corrected rake gets an assertion on the *context*
   and *value*, which is precisely what `master` gets wrong.
3. **Golden-file end-to-end tests** — the built binary over `tests/` fixtures
   (the `id_rsa`/`id_dsa`/`id_ecdsa` keys, `test1.sh`), comparing complete JSON and
   CSV output against checked-in goldens. Includes a test asserting output is
   byte-identical across `-j 1`, `-j 2`, and `-j 8`, pinning the ordering
   guarantee, and one asserting `sshpass` in `test1.sh` reports a non-empty value.

Tests run under `-race` in CI (`make race`) — the reason `OutputConfig` is
immutable rather than a set of globals.

## Makefile

```
all      build the datarake binary into golang/bin/
build    same as all
test     go test ./...
race     go test -race ./...
vet      go vet ./...
fmt      gofmt -l -w  (fmt-check fails on unformatted code)
tidy     go mod tidy
lint     vet + fmt-check
clean    remove bin/ and test cache
install  go install ./cmd/datarake
cross    linux/darwin/windows × amd64/arm64 into bin/
```

Version is read from the existing `project.properties` and injected with
`-ldflags -X main.version=`.

## Fidelity deltas from Python `master`

Consolidated list of every intentional behavior difference:

| # | Delta | Reason |
|---|---|---|
| 1 | No SARIF output | Requested |
| 2 | `entropy.py` absent | Requested; unreachable code |
| 3 | Non-empty contexts for `token`/`password`; non-empty values for `token`/`sshpass` | Decision #2 |
| 4 | Summary `lines` is N, not N+1 | Decision #3 |
| 5 | `ExcludeSubdirs`, `ExcludeFileExtensions`, `CommonTLDs` honored from config | Decision #4 |
| 6 | `.svn` not pruned under the shipped config; `.xyz` no longer a valid TLD | Consequence of #5 |
| 7 | Encoding *guess* may differ on non-UTF-8 input | Different detector implementation |
| 8 | Regex match timeout can skip a pathological line | Backtracking mitigation |
| 9 | `relPath` on `fullpath == basepath` returns empty rather than raising | Panic avoidance |
| 10 | `external_id`, `common_usernames`, `common_passwords` absent | Dead code |
| 11 | Directory entries traversed in sorted order | `os.walk` uses unsorted `scandir` order; Go's `filepath.WalkDir` sorts. Go's order is deterministic across runs and machines, which is what makes golden-file tests viable — Python's never was. |

Items 1–5 are deliberate and requested. Items 6–11 are consequences, each
documented at its call site in the Go source.

## Risks

- **Backtracking exposure.** Inherent to `regexp2`; bounded by `--match-timeout`,
  not eliminated. A hostile repository can still cost a timeout per line.
- **Filter-order sensitivity.** `FilterSet` expansion is order-preserving and
  filters are a denylist — any match drops the finding — so order does not affect
  the outcome, only the work. Worth an explicit test.
- **`regexp2` submatch semantics.** Leftmost-first, like Python. Confirmed on the
  config's real patterns, including both conditional-group branches, but the
  ported YAML rake tests are what keep this honest.
```
