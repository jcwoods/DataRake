import argparse
import csv
import json
import sys
import yaml

from .common import DirectoryWalker
from .common import RakeMatch
from .common import RakeSet

from .rakes import RakeContextPattern
from .rakes import RakeFileMeta
from .rakes import RakePattern

class DataRakeWriter(object):
    '''
    An abstract base class for all DataRake output formats.
    '''
    def __init__(self, fd=None,              # file/stream to be written
                       quiet:bool=False,     # quiet output enabled (--quiet)
                       summary:bool=True):   # summary output enabled (--summary)
        
        self._fd = fd
        self._quiet = quiet
        self._summary = summary
        return

    def initOutput(self):
        raise RuntimeError("abstract method called")

    def initSecrets(self):
        raise RuntimeError("abstract method called")

    def writeSecret(self, f):
        raise RuntimeError("abstract method called")

    def endSecrets(self):
        raise RuntimeError("abstract method called")

    def initSummary(self):
        raise RuntimeError("abstract method called")

    def writeSummary(self, s):
        raise RuntimeError("abstract method called")

    def endSummary(self):
        raise RuntimeError("abstract method called")

    def endOutput(self):
        raise RuntimeError("abstract method called")


class DataRakeCSVWriter(DataRakeWriter):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        return

    def initOutput(self):
        self._w = csv.writer(self._fd)
        return

    def initSecrets(self):
        if self._quiet: return
        self._w.writerow(RakeMatch.csv_header())
        return

    def writeSecret(self, f):
        if self._quiet: return
        self._w.writerow(f.aslist())

    def endSecrets(self):
        return

    def initSummary(self):
        return

    def writeSummary(self, s):
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

    def endSummary(self):
        return

    def endOutput(self):
        return


class DataRakeJSONWriter(DataRakeWriter):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        return

    def initOutput(self):
        print("{", end="", file=self._fd, flush=True)
        self._count = 0
        self._keys_written = 0
        return

    def initSecrets(self):
        if self._quiet: return
        print("\"secrets\": [", end="", file=self._fd, flush=True)
        self._keys_written += 1
        return

    def writeSecret(self, secret):
        if self._quiet: return
        if self._count > 0:
            print(",", end="", file=self._fd, flush=True)

        jtxt = json.dumps(secret.asdict())
        print(jtxt, end="", file=self._fd, flush=True)
        self._count += 1
        return

    def endSecrets(self):
        if self._quiet: return
        print("]", end="", file=self._fd, flush=True)

        return

    def initSummary(self):
        if not self._summary: return

        if self._keys_written > 0:
            print(",", end="", file=self._fd, flush=True)

        self._keys_written += 1
        print("\"summary\": ", end="", file=self._fd, flush=True)
        return

    def writeSummary(self, s):
        if not self._summary: return
        print(json.dumps(s), end="", file=self._fd, flush=True)
        return

    def endSummary(self):
        if not self._summary: return
        # do nothing
        return

    def endOutput(self):
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

    def initOutput(self):
        # per the SARIF standard, version and schema should appear first in
        # the output to permit "sniffing".  This data is constant anyway, so
        # it's not too much trouble to output it correctly.

        print('{"version": "2.1.0", ' \
              '"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json", ' \
              '"runs": [ { "tool": {"driver": {"name": "datarake"}},', \
              file=self._fd, end="", flush=True)
        return

    def initSecrets(self):
        print('"results": [ ', file=self._fd, end="", flush=True)
        self._count = 0
        return

    def writeSecret(self, secret):
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

    def endSecrets(self):
        print("]}", file=self._fd, end="", flush=True)
        return

    def initSummary(self):
        # summary not supported in SARIF
        return

    def writeSummary(self, s):
        # summary not supported in SARIF
        return

    def endSummary(self):
        # summary not supported in SARIF
        return

    def endOutput(self):
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

    parser.add_argument("-c", "--config", nargs=1, required=False, type=str, default="etc/datarake.yaml",
                        help="Configuration file")
    return parser.parse_args(argv[1:])

def loadConfig(cfile:str="etc/datarake.yaml"):
    with open(cfile, "r") as fd:
        cfg = yaml.safe_load(fd)

    verbose = bool(cfg.get('verbose', False))

    rs = RakeSet(verbose=verbose)

    for r in cfg['Rakes']:
        if   r['type'] == "ContextPattern": c = RakeContextPattern
        elif r['type'] == "FileMeta":       c = RakeFileMeta
        elif r['type'] == "SimplePattern":  c = RakePattern
        else:
            raise RuntimeError(f"ERROR: unsupported Rake type: {r['type']}")

        rake = c.load(r)
        rs.add(rake)

    return rs


def main(argv=sys.argv):
    cfg = parseCmdLine(argv)
    if cfg.secure: RakeMatch.set_secure()
    if cfg.disable_context: RakeMatch.disable_context()
    if cfg.disable_value: RakeMatch.disable_value()

    rs = loadConfig(cfg.config)
    sys.exit(0)

    if cfg.output is None:
        fd = sys.stdout
    else:
        fd = open(cfg.output[0], 'w', encoding='utf-8')

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
    for d in cfg.PATH:
        dw = DirectoryWalker(d, verbose=cfg.verbose)
        for context in dw:
            findings = rs.match(context)
            for f in findings:
                writer.writeSecret(f)

    writer.endSecrets()

    sfiles = rs.total_files
    slines = rs.total_lines
    shits = rs.total_hits      # yes, this I think this is funny ;)
    ssiz = rs.total_size
    summary = { "files": sfiles, "lines": slines, "hits": shits, "bytes": ssiz }

    writer.initSummary()
    writer.writeSummary(summary)
    writer.endSummary()

    writer.endOutput()
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))