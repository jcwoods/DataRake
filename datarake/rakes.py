import base64
import json
import re
import sys

from collections import deque

from .common import Rake
from .common import RakeMatch
from .common import RakeFilter
from .common import FilterRegistry

class RakeFileMeta(Rake):
    '''
    Creates RakeMatch based on file metadata (name, path, extension) rather
    than content.

    If self.all_required is set to true, all patterns which have been
    defined MUST return true.  Otherwise, we will return a positive
    result when the first match is made.

    Being a Rake applied to context (once per file rather than once per line),
    the match() method associated with a RakeFileMeta-based class must return
    either a single RakeMatch object or None (no match).
    '''

    def __init__(self, ptype:str, pdesc:str, severity:str,
                       path:str|None=None,    # pattern applied to path (dirname)
                       file:str|None=None,    # pattern applied to file name (basename)
                       ext:str|None=None,     # pattern applied to file extension
                       all:bool=True,     # pattern applied to path
                       ignorecase:bool=False,  # set re.IGNORECASE on regex matching
                       **kwargs):

        Rake.__init__(self, ptype, pdesc, severity, part='filemeta', **kwargs)

        f = re.IGNORECASE if ignorecase else 0
        self.path_pattern = None if path is None else re.compile(path, flags=f)
        self.file_pattern = None if file is None else re.compile(file, flags=f)
        self.ext_pattern = None if ext is None else re.compile(ext, flags=f)
        self.all_required = all
        return

    def match(self, context:dict):
        path = context.get('path', None)
        fnam = context.get('filename', None)
        ext = context.get('filetype', None)
        full = context.get('fullpath', None)
        basepath = context.get('basepath', None)

        # build with a relative path so filemeta findings are reported
        # consistently with content findings (which use relPath in RakePattern.match).
        relfile = self.relPath(basepath, full) if basepath is not None else full
        rm = RakeMatch(self, file=relfile, line=None)

        # Evaluate each defined pattern against the corresponding context field.
        # Skipping a check when the field is None counts as "not matched" rather
        # than "not defined" -- a file with no extension cannot satisfy an
        # extension pattern.
        checks = []
        if self.path_pattern is not None:
            checks.append(path is not None and self.path_pattern.match(path) is not None)
        if self.file_pattern is not None:
            checks.append(fnam is not None and self.file_pattern.match(fnam) is not None)
        if self.ext_pattern is not None:
            checks.append(ext is not None and self.ext_pattern.match(ext) is not None)

        if not checks: return None

        matched = all(checks) if self.all_required else any(checks)
        if not matched: return None

        if not self.filter(rm): return None
        return rm

    @staticmethod
    def load(config):
        '''
        Create a RakeFileMeta given a Rake configuration from datarake.yaml
        '''

        t = config.get('name', None)
        d = config.get('description', None)
        s = config.get('severity', None)
        p = config.get('path', None)
        f = config.get('file', None)
        e = config.get('extension', None)
        a = bool(config.get('all', True))
        i = bool(config.get('ignorecase', False))

        if t is None or d is None or s is None:
            raise RuntimeError(f"missing required configuration element(s) for rake: {t}")

        if p is None and f is None and e is None:
            raise RuntimeError(f"at least one of path, file, and extension must be set for rake: {t}")

        o = RakeFileMeta(t, d, s, path=p, file=f, ext=e, all=a, ignorecase=i)
        return o


class RakePattern(Rake):
    '''
    This is a basic pattern.  It will be compiled into a regex before use in
    matching.

    Note that the re.findall() method is used rather than a re.search() or
    re.match().  This affects the grouping and counting of the groups within
    the regex.

    Being a Rake applied to content (once per line rather than once per file),
    the match() method associated with a RakePattern-based class must return
    either a list of matches or an empty list.  All of the results returned
    in the list will be aggregated and returned as a combined group in RakeSet.
    '''

    def __init__(self, pattern:str, ptype:str, pdesc:str, severity:str,
                 ctx_group:int|None=None, key_group:int|None=None, val_group:int|None=None, ignorecase:bool=False):

        if ctx_group is None:
            raise RuntimeError(f"No context group given for Rake '{ptype}'")

        Rake.__init__(self, ptype, pdesc, severity, part='content')

        flags = 0
        if ignorecase:
            flags = re.IGNORECASE

        try:
            self.pattern = re.compile(pattern, flags=flags)
        except re.error as e:
            print(f"ERROR: failed to parse pattern: {pattern}", file=sys.stderr)
            sys.exit(1)

        self.ctx_group = ctx_group  # position (group) of context match in output tuple
        self.key_group = key_group  # position (group) of key match in output tuple
        self.val_group = val_group  # position (group) of value match in output tuple
        self.filters = list()

        return

    def addFilter(self, f:RakeFilter):
        self.filters.append(f)
        return

    def match(self, context:dict, text:str):
        mset = []

        # YAML configs index groups 0-based into a findall tuple (which omits
        # regex group 0). Translate to finditer's 1-based regex group number
        # by adding 1.
        relpath = None
        for m in self.pattern.finditer(text):
            kg = self.key_group + 1 if self.key_group is not None else None
            vg = self.val_group + 1 if self.val_group is not None else None
            cg = self.ctx_group + 1 if self.ctx_group is not None else None

            if relpath is None:
                relpath = self.relPath(context['basepath'], context['fullpath'])

            rm = RakeMatch(self,
                           file=relpath,
                           line=context['lineno'])

            if kg is not None and m.group(kg) is not None:
                start, end = m.span(kg)
                rm.set_key(m.group(kg), start, end - start)

            if vg is not None and m.group(vg) is not None:
                start, end = m.span(vg)
                rm.set_value(m.group(vg), start, end - start)

            if cg is not None and m.group(cg) is not None:
                start, end = m.span(cg)
                rm.set_context(m.group(cg), start, end - start)

            # Preserve findall's empty-string-for-unmatched-optional-group
            # semantics so filters that unpack match_groups still work.
            rm.match_groups = m.groups(default='')
            rm.full_context = context
            mset.append(rm)

        results = filter(self.filter, mset)
        return list(results)

    def filter(self, m:RakeMatch) -> bool:
        '''
        Check filters against given match.  Filters are a denylist: if any
        filter matches the result (eg, the value looks like a template
        variable or a known false positive), the result should be discarded.

        Returns False if the result should be filtered (dropped).
        '''

        for f in self.filters:
            if f.match(m): return False

        return True

    @staticmethod
    def load(config, filter_registry:FilterRegistry=None):
        '''
        Create a RakePattern given a Rake configuration from datarake.yaml.

        If filter_registry is supplied, `type: named` and `type: set` entries
        in the filter list are resolved against it; `type: set` references
        are expanded inline into the rake's filter list.
        '''

        n = config.get('name', "<-NotNamed->")
        p = config.get('pattern', None)
        d = config.get('description', "<-NoDesc->")
        s = config.get('severity', "LOW")
        kg = config.get('keygroup', None)
        cg = config.get('contextgroup', None)
        vg = config.get('valgroup', None)      # required, but enforced in init() method.
        i = config.get('ignorecase', False)

        if p is None:
            raise RuntimeError(f"pattern must be given for rake {n}")

        o = RakePattern(ptype = n, pdesc = d, severity = s, pattern = p,
                        ctx_group = cg, key_group = kg, val_group = vg, ignorecase = i)

        filters = config.get('filters', [])
        if not isinstance(filters, list):
            raise RuntimeError(f"filters must be a list for Rake {n}")

        if filter_registry is not None:
            resolved = filter_registry.load_list(filters)
        else:
            resolved = [RakeFilter.load(f) for f in filters]

        for fo in resolved:
            o.addFilter(fo)

        return o

class SentinelRake(Rake):
    '''
    A content rake that reports matches of `pattern` only when a `sentinel`
    pattern is observed nearby -- within `context_lines` lines, occurring
    either before or after the pattern.

    Motivating example: an AWS secret access key is a 40-character base64-ish
    string, far too generic to flag on its own.  But when one appears within a
    handful of lines of an AWS access key ID (the sentinel), the pair is a
    strong signal of leaked credentials.  The reported value is the `pattern`
    match (the secret); the sentinel must be present but is NOT itself part of
    the reported match.

    Detection is bidirectional without buffering past end-of-file: a rolling
    window of the last `context_lines` lines is kept, and on every line we
    check both directions --
      * a sentinel already in the window confirms a pattern on the new line, and
      * a sentinel on the new line confirms any not-yet-reported pattern earlier
        in the window.
    Because both rules only ever look *backwards*, every confirmable match is
    emitted as soon as the second of the (pattern, sentinel) pair is seen, so
    no flush hook is required.

    The rolling window is stored in the per-file `context` dict rather than on
    the rake instance, so a single shared rake object stays stateless and is
    safe to use concurrently across worker threads (see RakeSet.scan).
    '''

    def __init__(self, sentinel:str, pattern:str, ptype:str, pdesc:str,
                 severity:str, context_lines:int,
                 ctx_group:int, val_group:int,
                 ignorecase:bool=False):

        Rake.__init__(self, ptype, pdesc, severity, part='content')

        if context_lines < 0:
            raise RuntimeError(f"contextLines must be >= 0 for rake '{ptype}'")

        if ctx_group is None or val_group is None:
            raise RuntimeError(
                f"both contextgroup and valgroup are required for rake '{ptype}'")

        flags = re.IGNORECASE if ignorecase else 0
        try:
            self.sentinel = re.compile(sentinel, flags=flags)
            self.pattern = re.compile(pattern, flags=flags)
        except re.error:
            print(f"ERROR: failed to parse pattern for rake '{ptype}'", file=sys.stderr)
            sys.exit(1)

        self.context_lines = context_lines
        self.ctx_group = ctx_group  # group (of pattern) reported as context
        self.val_group = val_group  # group (of pattern) reported as the value
        self.filters = list()
        return

    def addFilter(self, f:RakeFilter):
        self.filters.append(f)
        return

    def filter(self, m:RakeMatch) -> bool:
        '''Denylist filter chain, identical in spirit to RakePattern.filter.'''
        for f in self.filters:
            if f.match(m): return False
        return True

    def _window(self, context:dict) -> deque:
        '''
        Return this rake's rolling line window for the current file, creating
        it on first use.  State lives in the (per-file, per-thread) context
        dict and is keyed by the rake instance so multiple SentinelRakes
        scanning the same file don't collide.
        '''
        states = context.setdefault('_sentinel_state', {})
        win = states.get(self)
        if win is None:
            win = deque()
            states[self] = win
        return win

    def match(self, context:dict, text:str):
        window = self._window(context)
        lineno = context['lineno']

        has_sentinel = self.sentinel.search(text) is not None
        pmatches = list(self.pattern.finditer(text))

        # relPath is only needed if this line carries pattern matches that
        # might eventually be reported -- compute it lazily to avoid the work
        # on the (common) lines that carry neither pattern nor sentinel.
        relpath = self.relPath(context['basepath'], context['fullpath']) \
            if pmatches else None

        record = {
            'lineno': lineno,
            'relpath': relpath,
            'has_sentinel': has_sentinel,
            # each entry: [regex match, reported?]
            'pmatches': [[m, False] for m in pmatches],
        }
        window.append(record)

        # Drop records that can no longer be within context_lines of the
        # current (or any future) line in either direction.
        while window and (lineno - window[0]['lineno']) > self.context_lines:
            window.popleft()

        results = []

        # Direction 1: sentinel before/on the pattern line.  Confirm pattern
        # matches on the current line against any sentinel already in window.
        if pmatches and any(rec['has_sentinel'] for rec in window):
            for entry in record['pmatches']:
                if entry[1]: continue
                entry[1] = True
                results.append(self._build_match(context, record, entry[0]))

        # Direction 2: pattern before the sentinel line.  A sentinel on the
        # current line confirms not-yet-reported pattern matches earlier in
        # the window.
        if has_sentinel:
            for rec in window:
                for entry in rec['pmatches']:
                    if entry[1]: continue
                    entry[1] = True
                    results.append(self._build_match(context, rec, entry[0]))

        return list(filter(self.filter, results))

    def _build_match(self, context:dict, record:dict, m:re.Match) -> RakeMatch:
        rm = RakeMatch(self, file=record['relpath'], line=record['lineno'])

        # Group numbers in the config are 0-based into a findall-style tuple
        # (which omits regex group 0); +1 maps to the finditer group number,
        # the same convention as RakePattern.  Both groups index into the
        # `pattern` match -- the sentinel is never part of the reported match.
        vg = self.val_group + 1
        cg = self.ctx_group + 1

        if m.group(vg) is not None:
            start, end = m.span(vg)
            rm.set_value(m.group(vg), start, end - start)

        if m.group(cg) is not None:
            start, end = m.span(cg)
            rm.set_context(m.group(cg), start, end - start)

        rm.match_groups = m.groups(default='')
        rm.full_context = context
        return rm

    @staticmethod
    def load(config, filter_registry:FilterRegistry=None):
        '''
        Create a SentinelRake given a Rake configuration from datarake.yaml.
        See RakePattern.load for the filter_registry contract.
        '''

        n = config.get('name', "<-NotNamed->")
        d = config.get('description', "<-NoDesc->")
        s = config.get('severity', "LOW")
        sentinel = config.get('sentinel', None)
        pattern = config.get('pattern', None)
        # `contextLines` is the documented key; accept `context` as an alias.
        cl = config.get('contextLines', config.get('context', None))
        cg = config.get('contextgroup', None)
        vg = config.get('valgroup', None)
        i = config.get('ignorecase', False)

        if sentinel is None or pattern is None:
            raise RuntimeError(f"sentinel and pattern must both be given for rake {n}")

        if cl is None:
            raise RuntimeError(f"contextLines must be given for rake {n}")

        if cg is None or vg is None:
            raise RuntimeError(f"contextgroup and valgroup must both be given for rake {n}")

        o = SentinelRake(sentinel=sentinel, pattern=pattern, ptype=n, pdesc=d,
                         severity=s, context_lines=int(cl),
                         ctx_group=cg, val_group=vg, ignorecase=i)

        filters = config.get('filters', [])
        if not isinstance(filters, list):
            raise RuntimeError(f"filters must be a list for Rake {n}")

        if filter_registry is not None:
            resolved = filter_registry.load_list(filters)
        else:
            resolved = [RakeFilter.load(f) for f in filters]

        for fo in resolved:
            o.addFilter(fo)

        return o


class RakeContextPattern(Rake):
    '''
    This rake binds patterns to file contexts (extension).

    Individual rakes (patterns) will be instantiated as RakePatterns, but will be applied by extension.
    '''

    def __init__(self, ptype:str, pdesc:str, severity:str):

        Rake.__init__(self, ptype, pdesc, severity)
        self.patterns = {}

        return

    def match(self, context:dict, text:str):
        mset = []  # TODO
        ft = context.get('filetype', None)

        # attempt to load a pattern for the current context
        p = self.patterns.get(ft, None)

        if p is None:
            # take default pattern if no match to context
            p = self.patterns.get(None, None)

        if p is None: return []  # if still no pattern, return no match.

        results = p.match(context, text)
        return results

    def addContext(self, ft:str, rp:RakePattern):
        '''
        Add a RakePattern (rp) to the given context (ctx)
        '''
        if self.patterns.get(ft, None) is not None:
            e = f"Multiple definitions for file type {ft} in rake {self.name}"
            raise RuntimeError(e)

        self.patterns[ ft ] = rp
        return

    @staticmethod
    def load(config, filter_registry:FilterRegistry=None):
        '''
        Create a RakeContextPattern given a Rake configuration from
        datarake.yaml.  See RakePattern.load for the filter_registry contract.
        '''

        n = config.get('name', "<-None->")
        d = config.get('description', "<-None->")
        s = config.get('severity', "LOW")

        rc = RakeContextPattern(n, d, s)

        for c in config.get("contexts", []):
            ctx = c.get('context', None)

            if not isinstance(ctx, list):    # these are the file types to which this pattern will be applied
                ctx = [ ctx ]

            p = c.get('pattern', None)
            kg = c.get('keygroup', None)
            cg = c.get('contextgroup', None)
            vg = c.get('valgroup', None)      # required, but enforced in init() method.
            i = c.get('ignorecase', False)

            if p is None:
                raise RuntimeError(f"pattern must be given for rake {n}:{c}")

            o = RakePattern(ptype = n, pdesc = d, severity = s, pattern = p,
                            ctx_group = cg, key_group = kg, val_group = vg, ignorecase = i)

            filters = c.get('filters', [])
            if not isinstance(filters, list):
                raise RuntimeError(f"filters must be a list for Rake {n}")

            if filter_registry is not None:
                resolved = filter_registry.load_list(filters)
            else:
                resolved = [RakeFilter.load(f) for f in filters]

            for fo in resolved:
                o.addFilter(fo)

            for ft in ctx:
                rc.addContext(ft, o)

        return rc


class RakeHostname(RakePattern):
    '''
    A RakeHostname acts as a 'root', meaning that it will match any valid hosts
    in the domain which share the root value.  For example, root="abc.com"
    will match not only "abc.com", but also "xyz.abc.com" and
    "foo.xyz.abc.com".

    A domain name may include A-Z, 0-9, and '-'.  The '-' may not appear at
    the beginning or end of the name.  A hostname must be less than 255
    characters in length, and no individual component of the hostname can
    exceed 63 characters.

    Any number of subdomains (equal to or beyond the depth inherent in the
    root) are supported.
    '''

    # a list of TLDs for hostname checks (these account for more than 99% of
    # hosts on the internet)
    TLDs = [ 'au', 'br', 'cn', 'com', 'de', 'edu', 'gov', 'in', 'info', 'ir',
             'mil', 'net', 'nl', 'org', 'ru', 'tk', 'top', 'uk', 'xyz' ]

    def __init__(self, domain:str|None=None, **kwargs):
        if domain is not None:
            d = re.escape(domain)
            r = r'\b(([a-z1-9\-]{1,63}\.)+' + d + r')\b'
        else:
            # going to make an arbitrary call here... domain must be 2 or
            # more "parts".  A name will need to be "host.d1.d2", We'll miss
            # things like "localhost.localdomain" but that should be
            # acceptable since we're not picking up 'a.b'-type symbols.  If
            # you don't like this, change the "{2,}" below to a simple "+".
            r = r'\b([a-z1-9\-]{1,63}(\.[a-z1-9\-]{1,63}){2,6})\b'

        rdesc = 'a hostname (possible information disclosure)'
        if domain is not None:
            rdesc += f" matching domain '{domain}'"

        RakePattern.__init__(self, r,
                                   'hostname',
                                   rdesc,
                                   "LOW",
                                   ctx_group=0,
                                   val_group=0,
                                   **kwargs)
        return

    @staticmethod
    def isValidHostname(fqdn:str, minparts:int=3):
        # length of FQDN must be <= 255
        l = len(fqdn)
        if l < 2 or l > 255: return False

        labels = fqdn.split(".")

        if len(labels) < minparts: return False

        # last label must be a valid TLD (we'll default to "common" here!)
        if labels[-1].lower() not in RakeHostname.TLDs:
            return False

        # each individual 
        for label in labels:
            if len(label) > 63: return False

        return True

    def filter(self, m:RakeMatch) -> bool:
        fqdn = m.value
        if not RakeHostname.isValidHostname(fqdn):
            return False

        return super().filter(m)


class RakeEmail(RakePattern):
    '''
    Detect email addresses.  If domain is not None, the domain associated with
    the email account must match the specified domain.
    '''

    def __init__(self, domain:str|None=None, **kwargs):
        if domain is not None:
            d = re.escape(domain)
            r = r'([a-zA-Z1-9_.\-]{1,63}@' + d + r')'
        else:
            r = r'([a-zA-Z0-9_.\-]{1,63}@[A-Za-z0-9_\-]{1,63}(\.[A-Za-z0-9_\-]{1,63}){1,6})'

        rdesc = 'an email address (possible information disclosure)'
        if domain is not None:
            rdesc += f" matching domain '{domain}'"

        RakePattern.__init__(self, r,
                                  'email',
                                  rdesc,
                                  'LOW',
                                  ctx_group=0, val_group=0,
                                  **kwargs)
        return

    def filter(self, m:RakeMatch) -> bool:
        email = m.value
        try:
            user, host = email.split("@")
        except ValueError:
            return False

        if not RakeHostname.isValidHostname(host, minparts=2):
            return False

        return super().filter(m)


class RakeBasicAuth(RakePattern):
    '''
    Find likely Basic auth tokens (as used in HTTP headers).  Eg,

        Authorization: Basic dXNlcjpwYXNzd29yZAo=

    Note that we use a minimum (practical) length of 16 when matching
    base64 data patterns.  If a potential base64-encoded value is found,
    we will decode it and make sure we have a ':' somewhere in the string
    as a minimal check.
    '''
    def __init__(self, minlen:int=16, encoding:str='utf-8', **kwargs):
        kp = r'(Basic ([A-Za-z0-9+/]{'+ str(minlen) + r',}={0,8}))$'
        RakePattern.__init__(self, kp,
                                  'auth basic',
                                  'possible value used with an Authorization: header',
                                  'HIGH',
                                  ctx_group=0, val_group=1, ignorecase=False, **kwargs)
        self.encoding = encoding
        return

    def filter(self, m:RakeMatch) -> bool:
        try:
            _, encoded = m.match_groups
            val = base64.b64decode(encoded, validate=True).decode(self.encoding).strip()
        except Exception:
            return False

        if not val.isprintable() or val.find(":") < 1:
            return False

        return super().filter(m)


class RakeJWTAuth(RakePattern):
    '''
    Find likely JWT tokens.  Eg,

    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG91IiwiaXNTb2NpYWwiOnRydWV9.4pcPyMD09olPSyXnrXCjTwXyr4BsezdI1AVTmud2fU4='

    This is three sections of data, formatted:  header.payload.signature

    The header and payload must be base64-encoded JSON.  We assume that the
    third section is either the signature or is non-standard, so we will make
    no attempt to decode or otherise validate it.

    Also note that we use a minimum (practical) length of 24 when matching
    base64 data patterns.  In reality, it would be difficult to encode a
    header or payload in this length, but it serves as an effective filter.

    JWT tokens are not supposed to include sensitive data, but they might
    still have been generated on a server and saved for use in later
    authorizations.  This STORAGE of JWT is dangerous and should be flagged.
    '''

    def __init__(self, encoding:str='utf-8', **kwargs):
        kp = r'\b(([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/_-]{24,}={0,2}))\b'
        RakePattern.__init__(self, kp,
                                  'auth jwt',
                                  'possible JavaScript web token',
                                  'MEDIUM',
                                  ctx_group=0, val_group=0,
                                  ignorecase=False, **kwargs)

        self.encoding = encoding
        return

    def filter(self, m:RakeMatch) -> bool:
        try:
            _, header_b64, payload_b64, _ = m.match_groups
        except (AttributeError, ValueError):
            return False

        # Header and payload must both base64-decode and JSON-parse for this
        # to plausibly be a JWT; the signature is opaque and not checked.
        for st in (header_b64, payload_b64):
            try:
                st_padded = st + ("=" * (len(st) % 4))
                td = base64.b64decode(st_padded).decode('utf-8')
                json.loads(td)
            except Exception:
                return False

        return super().filter(m)
