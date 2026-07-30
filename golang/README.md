# datarake (Go)

A Go port of [datarake](https://github.com/jcwoods/datarake), a secrets scanner
for use inside or outside a pipeline. It reads the same `datarake.yaml`
configuration syntax and emits the same JSON and CSV output formats as the
Python implementation.

## Building

The module lives in `golang/` and builds with Go 1.22 or newer.

```sh
cd golang
make            # build ./bin/datarake
make test       # go test ./...
make race       # go test -race ./...
make lint       # go vet + gofmt check
make cross      # build linux/darwin/windows for amd64 and arm64
make clean      # remove ./bin and the test cache
```

From the repository root:

```sh
make golang        # build the Go binary
make golang-test   # run the Go test suite
```

## Running

```sh
./bin/datarake [options] [PATH ...]
```

`PATH` defaults to `.` and may be repeated. Each path may be a directory or a
single file.

| Flag | Default | Description |
|---|---|---|
| `-f`, `--format` | `json` | Output format: `csv` or `json` |
| `-o`, `--output` | stdout | Write output to this file |
| `-s`, `--secure` | off | Secure mode: no secret values, contexts replaced by an md5 tracking hash |
| `--disable-context` (`-dx`) | off | Omit the context from output |
| `--disable-value` (`-dv`) | off | Omit the matched secret from output |
| `-u`, `--summary` | off | Emit summary statistics |
| `-q`, `--quiet` | off | Suppress findings; summary only |
| `-v`, `--verbose` | off | Diagnostic output on stderr |
| `-j`, `--jobs` | CPU count | Number of concurrent file scanners |
| `-c`, `--config` | bundled | Configuration file; defaults to the embedded `datarake.yaml` |
| `--match-timeout` | `1s` | Per-line regex match timeout |

`-dx` and `-dv` are accepted for compatibility with the Python CLI's argparse
spelling; `--disable-context` and `--disable-value` are the canonical forms.

### Example

```sh
$ printf 'username=jeffw\npassword=Sup3rSekrit!\n' > /tmp/scan/project.properties
$ ./bin/datarake -f json -u /tmp/scan
{"secrets": [{"path": "project.properties", "line": 2, "type": "password", "description": "possible plaintext password", "severity": "HIGH", "context": {"value": "password=Sup3rSekrit!", "offset": 0, "length": 21}, "value": {"value": "Sup3rSekrit!", "offset": 9, "length": 12}}],"summary": {"files": 1, "lines": 2, "hits": 1, "bytes": 37}}
```

Offsets and lengths are measured in characters (runes), not bytes, matching
Python's string indexing.

## Concurrency

One goroutine scans each file, bounded by `--jobs`. The main goroutine drains
results oldest-first, so output order follows directory-walk order and is
byte-identical at any `-j`. Only the main goroutine writes output; workers
compute and return.

## Regular expressions

This port uses [`regexp2`](https://github.com/dlclark/regexp2) rather than Go's
standard `regexp`. The shipped configuration relies on backreferences and
conditional groups, which RE2 cannot express, and `regexp2` indexes in runes
rather than bytes, which keeps the reported offsets correct on non-ASCII lines.

The tradeoff is that `regexp2` backtracks and so has no linear-time guarantee. A
pathological line can be expensive. Every compiled pattern therefore carries a
match timeout, `--match-timeout` (default 1s); a line that exceeds it is skipped
rather than allowed to hang the scan. This bounds the exposure but does not
eliminate it: a hostile repository can still cost one timeout per line.

## Differences from the Python implementation

Every intentional behavior difference from Python `master`:

| # | Delta | Reason |
|---|---|---|
| 1 | No SARIF output | Requested |
| 2 | `entropy.py` absent | Requested; unreachable code |
| 3 | Non-empty contexts for `token`/`password`; non-empty values for `token`/`sshpass` | Corrected config group numbers |
| 4 | Summary `lines` is N, not N+1 | Off-by-one fix |
| 5 | `ExcludeSubdirs`, `ExcludeFileExtensions`, `CommonTLDs` honored from config | Previously parsed by nobody |
| 6 | `.svn` not pruned under the shipped config; `.xyz` no longer a valid TLD | Consequence of #5 |
| 7 | Encoding *guess* may differ on non-UTF-8 input | Different detector implementation |
| 8 | Regex match timeout can skip a pathological line | Backtracking mitigation |
| 9 | `relPath` on `fullpath == basepath` returns empty rather than raising | Panic avoidance |
| 10 | `external_id`, `common_usernames`, `common_passwords` absent | Dead code |
| 11 | Directory entries traversed in sorted order | `os.walk` uses unsorted `scandir` order; Go's `filepath.WalkDir` sorts. Go's order is deterministic across runs and machines, which is what makes golden-file tests viable — Python's never was. |

Items 1–5 are deliberate. Items 6–11 are consequences, each documented at its
call site in the source.

On #3: the Python README documents a `password=Sup3rSekrit!` finding whose
context is the full assignment, but `master` reports an empty context for it.
The config's group numbers are 0-based indexes into a `findall` tuple that omits
group 0, so config group *k* is regex group *k+1*; several rakes were off by one.
This port corrects them, which is why the example above produces the context the
Python README always described.

### Encoding

Charset detection samples the head of each file. Go's detector is not Python's
`chardet`, so the guess can differ on non-UTF-8 input; UTF-8 and ASCII are
unaffected. Files detected as UTF-8 or ASCII are decoded strictly, so malformed
input is reported as undecodable and its line count zeroed, matching Python's
`UnicodeDecodeError` handling. Single-byte charsets (ISO-8859-1, windows-125x)
map all 256 byte values and so never fail to decode, in either implementation.

### Reserved configuration keys

Four keys are parsed but deliberately wired to nothing:

- `Global.IgnorePasswords`
- `Global.IgnoreUsers`
- `Global.IgnoreHosts`
- `skipcontexts` on the `token` rake

No code path in the Python consumes these, or anything equivalent. Honoring them
would add suppression behavior that has never existed in the tool, which is a new
feature rather than a port. They are read and retained so the configuration
round-trips unchanged and so the behavior can be added deliberately later.

The `private key` rake's `type: literal, value: ENCRYPTED` filter is likewise
inert, in this port and in Python: the rake defines no `valgroup`, so a match
carries no value, and a literal filter matching on value returns false whenever
the value is unset. An encrypted private key header is therefore still reported.
Making that filter work requires adding a `valgroup` to `datarake.yaml`, which
changes what the scanner reports and is out of scope for a port.

## Layout

| Path | Responsibility |
|---|---|
| `match/` | `RakeMatch`, the finding record, and `OutputConfig` |
| `filter/` | Denylist filters and the `NamedFilter`/`FilterSet` registry |
| `rake/` | The finders: patterns, file metadata, contexts, hostnames, auth tokens |
| `rakeset/` | Applies a set of rakes to a file; encoding detection and line reading |
| `walker/` | Directory traversal |
| `writer/` | CSV and JSON output |
| `config/` | YAML loading and `RakeSet` construction |
| `cmd/datarake/` | CLI and the scan pipeline |
