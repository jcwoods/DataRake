import argparse
import csv
import json
import sys

from datarake import DirectoryWalker, RakeMatch
from datarake import RakeSet, RakeHostname, RakeEmail
from datarake import RakeJWTAuth, RakeURL, RakePassword, RakeToken
from datarake import RakeAWSHMACAuth, RakeBasicAuth, RakeBearerAuth
from datarake import RakePrivateKey, RakeSSHIdentity, RakeNetrc, RakeSSHPass
from datarake import RakePKIKeyFiles, RakeHtpasswdFiles, RakeKeystoreFiles

def parseCmdLine(argv):
    parser = argparse.ArgumentParser()

    # add OPTIONAL arguments
    parser.add_argument("-n", "--hostname", action='store_true',
                        required=False, default=False,
                        help="scan for hostnames, optionally rooted in DOMAIN.")
    parser.add_argument("-e", "--email", action='store_true',
                        required=False, default=False,
                        help="scan for email addresses, optionally rooted in DOMAIN.")
    parser.add_argument("-d", "--domain", nargs=1,
                        required=False, default=None,
                        help="for hostname and emails, require that they are "
                             "rooted in DOMAIN.  If no DOMAIN is specified and "
                             "either hostname or email matching is enabled, any "
                             "pattern matching a host or email will be reported")
    parser.add_argument("-j", "--jwt", action='store_true',
                        required=False, default=False,
                        help="scan for Javascript Web Tokens (JWT)")

    # allow DEFAULT arguments to be disabled.
    parser.add_argument("-dp", "--disable-passwords", action='store_true',
                        required=False, default=False,
                        help="disable scan for passwords")
    parser.add_argument("-dt", "--disable-tokens", action='store_true',
                        required=False, default=False,
                        help="disable scan for tokens")
    parser.add_argument("-dh", "--disable-headers", action='store_true',
                        required=False, default=False,
                        help="disable scan for common auth headers")
    parser.add_argument("-dk", "--disable-private-keys", action='store_true',
                        required=False, default=False,
                        help="disable scan for private key files.")
    parser.add_argument("-du", "--disable-urls", action='store_true',
                        required=False, default=False,
                        help="disable scan for credentials in URLs")
    parser.add_argument("-df", "--disable-dangerous-files", action='store_true',
                        required=False, default=False,
                        help="disable detection of dangerous files")
    parser.add_argument("-dc", "--disable-dangerous-commands", action='store_true',
                        required=False, default=False,
                        help="disable detection of dangerous commands")

    parser.add_argument("PATH", default=["."], nargs="*",
                        help="Path to be (recursively) searched.")

    # output formatting
    parser.add_argument("-f", "--format", nargs=1, required=False, type=str,
                        choices=["csv", "json"], default=["csv"],
                        help="Output format")
    parser.add_argument("-o", "--output", nargs=1, required=False, type=str, default=None,
                        help="Output location (defaults to stdout)")
    parser.add_argument("-s", "--secure", required=False, action="store_true", default=False,
                        help="Enable secure output mode (no secrets displayed)")
    parser.add_argument("-dx", "--disable-context", required=False, action="store_true", default=False,
                        help="Disable output of context match")
    parser.add_argument("-dv", "--disable-value", required=False, action="store_true", default=False,
                        help="Disable output of secret match")

    parser.add_argument("-v", "--verbose", required=False, action="store_true", default=False,
                        help="Enable verbose (diagnostic) output")

    return parser.parse_args(argv[1:])


def main(argv=sys.argv):
    cfg = parseCmdLine(argv)
    if cfg.output is None:
        fd = sys.stdout
    else:
        fd = open(cfg.output[0], 'w', encoding='utf-8')

    if cfg.secure: RakeMatch.set_secure()
    if cfg.disable_context: RakeMatch.disable_context()
    if cfg.disable_value: RakeMatch.disable_value()

    rs = RakeSet(verbose=cfg.verbose)

    if cfg.hostname:
        rs.add(RakeHostname(domain = cfg.domain))

    if cfg.email:
        rs.add(RakeEmail(domain = cfg.domain))

    if cfg.jwt:
        rs.add(RakeJWTAuth())

    if not cfg.disable_urls:
        rs.add(RakeURL())

    if not cfg.disable_passwords:
        rs.add(RakePassword())

    if not cfg.disable_passwords:
        rs.add(RakeToken())

    if not cfg.disable_headers:
        rs.add(RakeAWSHMACAuth())
        rs.add(RakeBasicAuth())
        rs.add(RakeBearerAuth())

    if not cfg.disable_private_keys:
        rs.add(RakePrivateKey())

    if not cfg.disable_dangerous_files:
        rs.add(RakeSSHIdentity())
        rs.add(RakeNetrc())
        rs.add(RakePKIKeyFiles())
        rs.add(RakeHtpasswdFiles())
        rs.add(RakeKeystoreFiles())

    if not cfg.disable_dangerous_commands:
        rs.add(RakeSSHPass())

    vn = 0  # count of output vulnerabilities
    out_format = cfg.format[0]
    if out_format == 'csv':
        w = csv.writer(fd)
        w.writerow(RakeMatch.csv_header())

    if out_format == 'json':
        print("[", file=fd, flush=True)
    
    for d in cfg.PATH:
        dw = DirectoryWalker(d, verbose=cfg.verbose)
        for context in dw:
            findings = rs.match(context)
            for f in findings:

                if out_format == 'json':
                    if vn > 0:
                        print(",", file=fd, flush=True)            

                    vuln = f.asdict()
                    jtxt = json.dumps(vuln, indent=4, sort_keys=True)
                    print(jtxt, end='', file=fd, flush=True)

                else: # out_format == 'csv'
                    w.writerow(f.aslist())

                vn += 1

    if out_format == 'json':
        print("]", file=fd, flush=True)

    fd.close()
    if cfg.verbose:
        print("* Processing completed.", file=sys.stderr)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
