import argparse
import csv
import json
import os
import sys
import yaml

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import TextIO

from .common import DirectoryWalker
from .common import FilterRegistry
from .common import RakeFilter
from .common import RakeMatch
from .common import RakeSet

from .rakes import RakeContextPattern
from .rakes import RakeFileMeta
from .rakes import RakePattern

class DataRakeWriter(object):
    '''
    An abstract base class for all DataRake output formats.
    '''
    def __init__(self, fd:TextIO=sys.stdout, # file/stream to be written
                       quiet:bool=False,     # quiet output enabled (--quiet)
                       summary:bool=True):   # summary output enabled (--summary)
        
        self._fd = fd
        self._quiet = quiet
        self._summary = summary
        return

    def initOutput(self) -> None:
        raise RuntimeError("abstract method called")

    def initSecrets(self) -> None:
        raise RuntimeError("abstract method called")

    def writeSecret(self, secret) -> None:
        raise RuntimeError("abstract method called")

    def endSecrets(self) -> None:
        raise RuntimeError("abstract method called")

    def initSummary(self) -> None:
        raise RuntimeError("abstract method called")

    def writeSummary(self, s) -> None:
        raise RuntimeError("abstract method called")

    def endSummary(self) -> None:
        raise RuntimeError("abstract method called")

    def endOutput(self) -> None:
        raise RuntimeError("abstract method called")


class DataRakeCSVWriter(DataRakeWriter):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        return

    def initOutput(self) -> None:
        self._w = csv.writer(self._fd)
        return

    def initSecrets(self) -> None:
        if self._quiet: return
        self._w.writerow(RakeMatch.csv_header())
        return

    def writeSecret(self, secret) -> None:
        if self._quiet: return
        self._w.writerow(secret.aslist())

    def endSecrets(self) -> None:
        return

    def initSummary(self) -> None:
        return

    def writeSummary(self, s) -> None:
        if not self._summary: return

        files = s.get('files', 0)
        lines = s.get('lines', 0)
        size = s.get('bytes', 0)
        hits = s.get('hits', 0)

        print(f"files: {files}", file=self._fd, flush=True)
        print(f"lines: {lines}", file=self._fd, flush=True)
        print(f"bytes: {size}", file=self._fd, flush=True)
        print(f"hits: {hits}", file=self._fd, flush=True)
        return

    def endSummary(self) -> None:
        return

    def endOutput(self) -> None:
        return


class DataRakeJSONWriter(DataRakeWriter):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        return

    def initOutput(self) -> None:
        print("{", end="", file=self._fd, flush=True)
        self._count = 0
        self._keys_written = 0
        return

    def initSecrets(self) -> None:
        if self._quiet: return
        print("\"secrets\": [", end="", file=self._fd, flush=True)
        self._keys_written += 1
        return

    def writeSecret(self, secret) -> None:
        if self._quiet: return
        if self._count > 0:
            print(",", end="", file=self._fd, flush=True)

        jtxt = json.dumps(secret.asdict())
        print(jtxt, end="", file=self._fd, flush=True)
        self._count += 1
        return

    def endSecrets(self) -> None:
        if self._quiet: return
        print("]", end="", file=self._fd, flush=True)

        return

    def initSummary(self) -> None:
        if not self._summary: return

        if self._keys_written > 0:
            print(",", end="", file=self._fd, flush=True)

        self._keys_written += 1
        print("\"summary\": ", end="", file=self._fd, flush=True)
        return

    def writeSummary(self, s) -> None:
        if not self._summary: return
        print(json.dumps(s), end="", file=self._fd, flush=True)
        return

    def endSummary(self) -> None:
        if not self._summary: return
        # do nothing
        return

    def endOutput(self) -> None:
        print("}", file=self._fd, flush=True)
        return


class DataRakeSARIFWriter(DataRakeWriter):
    '''
    Generate SARIF output.  See:
        https://github.com/microsoft/sarif-tutorials/blob/main/README.md).
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        return

    def initOutput(self) -> None:
        # per the SARIF standard, version and schema should appear first in
        # the output to permit "sniffing".  This data is constant anyway, so
        # it's not too much trouble to output it correctly.

        print('{"version": "2.1.0", ' \
              '"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json", ' \
              '"runs": [ { "tool": {"driver": {"name": "datarake"}},', \
              file=self._fd, end="", flush=True)
        return

    def initSecrets(self) -> None:
        print('"results": [ ', file=self._fd, end="", flush=True)
        self._count = 0
        return

    def writeSecret(self, secret) -> None:
        # we do need to be careful with the output here -- it originates from
        # the files being scanned and needs to be properly escaped.  We'll
        # build it into a dict and then use the json module to output it
        # safely.

        line = secret.line if secret.line is not None else 0
        startPos = secret.value_offset if secret.value_offset is not None else 0
        length = secret.value_length if secret.value_length is not None else 0
        endPos = startPos + length

        o = {   "ruleId": secret.label,
                "level": "warning",
                "message": {
                    "text": secret.description
                },
                "locations": [
                    { 
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": secret.file
                            },
                            "region": {
                                "startLine": line,
                                "startColumn": startPos,
                                "endColumn": endPos
                            }
                        }
                    }
                ]
            }

        if self._count > 0: print(",", file=self._fd, flush=True)
        print(json.dumps(o), file=self._fd, end="", flush=True)
        self._count += 1
        return

    def endSecrets(self) -> None:
        print("]}", file=self._fd, end="", flush=True)
        return

    def initSummary(self) -> None:
        # summary not supported in SARIF
        return

    def writeSummary(self, s) -> None:
        # summary not supported in SARIF
        return

    def endSummary(self) -> None:
        # summary not supported in SARIF
        return

    def endOutput(self) -> None:
        print("]}", file=self._fd, end="\n", flush=True)


def parseCmdLine(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("PATH", default=["."], nargs="*",
                        help="Path to be (recursively) searched.")

    # output formatting
    parser.add_argument("-f", "--format", nargs=1, required=False, type=str,
                        choices=["csv", "json", "sarif"], default=["json"],
                        help="Output format")
    parser.add_argument("-o", "--output", nargs=1, required=False, type=str, default=None,
                        help="Output location (defaults to stdout)")
    parser.add_argument("-s", "--secure", required=False, action="store_true", default=False,
                        help="Enable secure output mode (no secrets displayed, secure context)")
    parser.add_argument("-dx", "--disable-context", required=False, action="store_true", default=False,
                        help="Disable output of context match")
    parser.add_argument("-dv", "--disable-value", required=False, action="store_true", default=False,
                        help="Disable output of secret matched")
    parser.add_argument("-u", "--summary", required=False, action="store_true", default=False,
                        help="enable output of summary statistics")
    parser.add_argument("-q", "--quiet", required=False, action="store_true", default=False,
                        help="Do not output scan results, summary information only.")

    parser.add_argument("-v", "--verbose", required=False, action="store_true", default=False,
                        help="Enable verbose (diagnostic) output")

    parser.add_argument("-j", "--jobs", required=False, type=int, default=None,
                        help="Number of worker threads used to scan files "
                             "(default: CPU count)")

    parser.add_argument("-c", "--config", required=False, type=str, default=None,
                        help="Configuration file (defaults to the bundled datarake.yaml)")
    return parser.parse_args(argv[1:])


def _default_config_text() -> str:
    '''Return the contents of the bundled datarake.yaml shipped inside the
    package.

    We read through the importlib.resources Traversable API rather than
    converting to a filesystem path and opening it.  This works whether the
    package is installed as a directory, a zipped egg/wheel, or run from a
    source checkout -- a plain str(path) + open() breaks for zipped installs
    because the resource has no real filesystem path.
    '''
    from importlib.resources import files
    return files('datarake').joinpath('datarake.yaml').read_text(encoding='utf-8')

def _buildFilterRegistry(cfg:dict) -> FilterRegistry:
    '''Construct a FilterRegistry from the top-level FilterRegistry: section
    of the YAML config.

    The section is a list whose entries are single-key dicts:
        - NamedFilter:
            - name: X
              type: regex
              ...
        - FilterSet:
            - name: Y
            - filters: [ ... ]

    NamedFilter items are full filter definitions plus a name; FilterSet items
    are split across separate list entries for name and filters, which we
    merge here.
    '''
    registry = FilterRegistry()

    for entry in cfg.get('FilterRegistry', []) or []:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise RuntimeError(
                f"FilterRegistry entries must be single-key dicts "
                f"(NamedFilter or FilterSet); got: {entry!r}")

        kind, items = next(iter(entry.items()))

        if kind == "NamedFilter":
            for item in items or []:
                name = item.get('name')
                if name is None:
                    raise RuntimeError("NamedFilter entry missing 'name'")
                flt_cfg = {k: v for k, v in item.items() if k != 'name'}
                registry.register_named(name, RakeFilter.load(flt_cfg))

        elif kind == "FilterSet":
            # FilterSet items in this YAML schema are a list where one item
            # carries 'name' and another carries 'filters'.  Merge them.
            merged = {}
            for d in items or []:
                if isinstance(d, dict):
                    merged.update(d)
            name = merged.get('name')
            if name is None:
                raise RuntimeError("FilterSet entry missing 'name'")
            filters = registry.load_list(merged.get('filters', []) or [])
            registry.register_set(name, filters)

        else:
            raise RuntimeError(f"Unknown FilterRegistry entry kind: {kind!r}")

    return registry


def loadConfig(cfile:str=None):
    if cfile is None:
        # Use the config bundled inside the package (zip-safe).
        cfg = yaml.safe_load(_default_config_text())
    else:
        with open(cfile, "r") as fd:
            cfg = yaml.safe_load(fd)

    verbose = bool(cfg.get('verbose', False))

    # FilterRegistry must be built first so references in rake configs resolve.
    registry = _buildFilterRegistry(cfg)

    rs = RakeSet(verbose=verbose)

    for r in cfg['Rakes']:
        if   r['type'] == "ContextPattern": c = RakeContextPattern
        elif r['type'] == "FileMeta":       c = RakeFileMeta
        elif r['type'] == "SimplePattern":  c = RakePattern
        else:
            raise RuntimeError(f"ERROR: unsupported Rake type: {r['type']}")

        # Only filter-bearing rakes accept filter_registry; FileMeta has no
        # filters configured today, so it uses the legacy load() signature.
        if c is RakeFileMeta:
            rake = c.load(r)
        else:
            rake = c.load(r, filter_registry=registry)
        rs.add(rake)

    return rs


def main(argv=sys.argv):
    cfg = parseCmdLine(argv)
    if cfg.secure: RakeMatch.set_secure()
    if cfg.disable_context: RakeMatch.disable_context()
    if cfg.disable_value: RakeMatch.disable_value()

    rs = loadConfig(cfg.config)

    if cfg.output is None:
        fd = sys.stdout
        close_fd = False
    else:
        fd = open(cfg.output[0], 'w', encoding='utf-8')
        close_fd = True

    jobs = cfg.jobs if (cfg.jobs and cfg.jobs > 0) else (os.cpu_count() or 1)

    try:
        out_format = cfg.format[0]

        # verbosity:  secure quiet summary
        if out_format == 'csv':
            writer = DataRakeCSVWriter(fd=fd, quiet=cfg.quiet, summary=cfg.summary)
        elif out_format == 'sarif':
            writer = DataRakeSARIFWriter(fd=fd, quiet=cfg.quiet, summary=cfg.summary)
        else:
            writer = DataRakeJSONWriter(fd=fd, quiet=cfg.quiet, summary=cfg.summary)

        writer.initOutput()
        writer.initSecrets()

        # Running totals are owned solely by the main thread.
        totals = {"files": 0, "lines": 0, "hits": 0, "bytes": 0}

        # The main thread's only jobs are (1) hand files to workers and
        # (2) write the results workers return.  Worker threads scan files
        # via RakeSet.scan() but NEVER write output.  We bound the number of
        # in-flight scans so a huge tree doesn't materialize all futures and
        # their findings at once.
        max_in_flight = max(jobs * 4, jobs)

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            pending = deque()

            def drain_one():
                # Block on the oldest outstanding scan (preserving directory
                # walk order) and emit its results -- from the main thread.
                # A failure scanning one file is logged and skipped rather
                # than aborting the entire run.
                ctx, future = pending.popleft()
                try:
                    findings, stats = future.result()
                except Exception as e:
                    print(f"* ERROR scanning {ctx.get('fullpath', ctx)}: {e}",
                          file=sys.stderr)
                    return
                for f in findings:
                    writer.writeSecret(f)
                for k in totals:
                    totals[k] += stats[k]

            for d in cfg.PATH:
                for context in DirectoryWalker(d, verbose=cfg.verbose):
                    pending.append((context, pool.submit(rs.scan, context)))
                    if len(pending) >= max_in_flight:
                        drain_one()

            # Drain any remaining scans before the pool is shut down.
            while pending:
                drain_one()

        # ThreadPoolExecutor.__exit__ has now shut down the worker threads.
        writer.endSecrets()

        writer.initSummary()
        writer.writeSummary(totals)
        writer.endSummary()

        writer.endOutput()
    finally:
        if close_fd:
            fd.close()

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))