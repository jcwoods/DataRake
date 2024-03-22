import base64
import json
import re
import sys

from .common import RakeMatch

class Rake(object):
    '''
    A Rake is an abstract "issue finder".  Its subclasses do all of the real
    work.  When applied or executed, it creates RakeMatch objects.  Rake
    objects are grouped in RakeSet collections when many Rakes will be
    applied repeatedly.
    '''

    # some common values used in Rake filters
    common_usernames = [ 'username', 'usern', 'user' ]
    common_passwords = [ 'password', 'passwd', 'passw', 'pass' ]

    def __init__(self, ptype:str, pdesc:str, severity:str, part:str='content'):

        if part not in ['content', 'filemeta']:
            raise RuntimeError(f"Invalid part in Rake initializer: {part}")

        self.name = self.__class__.__name__
        self.ptype = ptype        # rake type (password, token, private key, etc)
        self.pdesc = pdesc        # long(er) description of rake
        self.severity = severity  # finding severity
        self.part = part          # where is rake applied? (content, filemeta, etc.)
        return

    def __str__(self):
        return f"<Rake({self.name}, {self.ptype}, {self.part})>"

    @staticmethod
    def relPath(basepath:str, fullpath:str):

        bplen = len(basepath)
        relpath = fullpath[bplen:]

        while relpath[0] == '/':
            relpath = relpath[1:]

        return  relpath

    def filter(self, m:RakeMatch):
        '''
        A generic filter method.  If filter() returns false (eg, a match should
        be filtered), the result will not be added to the result set.

        Note that this is only a fail-safe, and that filters must be
        implemented within the context of a specific Rake-type.  The 'm'
        (match) parameter may be of different types and must be interpreted
        differently.
        '''
        return True

class RakeLiteralFilter:   # forward declaration
    pass

class RakeRegexFilter:     # forward declaration
    pass

class RakeFilter(object):
    def __init__(self, ignorecase:bool=False):
        self.ignorecase = ignorecase
        return

    @staticmethod
    def load(config:dict):
        t = config.get('type', None)
        if t is None: raise RuntimeError("Filter type not specified.")

        if t.lower() == "regex":
            return RakeRegexFilter.load(config)

        if t.lower() == "literal":
            return RakeRegexFilter.load(config)

        raise RuntimeError(f"Invalid filter type: {t}")
    
    def match(self, context:RakeMatch):
        raise RuntimeError("Abstract method RakeFilter.match() called")


class RakeLiteralFilter(RakeFilter):
    def __init__(self, key:str=None, val:str=None, ignorecase:bool=False):
        RakeFilter.__init__(self, ignorecase = ignorecase)

        if key is None and val is None:
            raise RuntimeError("One of key or value must be set for literal filter.")

        if self.ignorecase:
            key = key.lower() if key is not None else None
            val = val.lower() if val is not None else None

        self._key = key
        self._val = val
        return

    def __str__(self):
        return f"<RakeLiteralFilter(key={self._key}, val={self._val})>"

    def match(self, match:RakeMatch):
        # Note that one of self._val or self._key MUST be set.
        if self._val is not None:
            v = match.value
            if self.ignorecase:
                v = v.lower()
            
            if v != self._val: return False

        if self._key is not None:
            k = match.key
            if self.ignorecase:
                k = k.lower()
            
            if k != self._key: return False

        return True

    @staticmethod
    def load(config:dict):
        k = config.get('key', None)
        v = config.get('value', None)
        i = config.get('ignorecase', False)
        return RakeLiteralFilter(key=k, val=v, ignorecase=i)


class RakeRegexFilter(RakeFilter):
    def __init__(self, key:str=None, val:str=None, ignorecase:bool=False):
        RakeFilter.__init__(self, ignorecase = ignorecase)

        if key is None and val is None:
            raise RuntimeError("One of key or value must be set for regex filter.")

        flags = 0   # default re flags
        if self.ignorecase:
            flags = re.IGNORECASE

        self._key = re.compile(key, flags=flags) if key is not None else None
        self._val = re.compile(val, flags=flags) if val is not None else None

        return

    def __str__(self):
        return f"<RakeRegexFilter(key={self._key}, val={self._val})>"

    def match(self, match:RakeMatch):
        # Note that one of self._val or self._key MUST be set.
        if self._val is not None:
            mv = match.value
            if not self._val.match(mv): return False
            
        if self._key is not None:
            mk = match.key
            if not self._key.match(mk): return False
            
        return True

    @staticmethod
    def load(config:dict):
        k = config.get('key', None)
        v = config.get('value', None)
        i = config.get('ignorecase', False)
        return RakeRegexFilter(key=k, val=v, ignorecase=i)


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
                       path:str=None,    # pattern applied to path (dirname)
                       file:str=None,    # pattern applied to file name (basename)
                       ext:str=None,     # pattern applied to file extension
                       all:str=True,     # pattern applied to path
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

        # create the match up front, just in case!
        rm = RakeMatch(self, file=full, line=None)
        any_part = False

        if self.path_pattern is not None:
            pm = self.path_pattern.match(path)
            if not self.all_required and pm is not None: return rm
            if self.all_required and pm is None: return None
            any_part = True

        if self.file_pattern is not None:
            fm = self.file_pattern.match(fnam)
            if not self.all_required and fm is not None: return rm
            if self.all_required and fm is None: return None
            any_part = True

        if self.ext_pattern is not None and ext is not None:
            xm = self.ext_pattern.match(ext)
            if not self.all_required and xm is not None: return rm
            if self.all_required and xm is None: return None
            any_part = True

        if self.filter(rm): return None
        if any_part: return rm
        return None

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

        if t is None or d is None or s is None:
            raise RuntimeError(f"missing required configuration element(s) for rake: {t}")

        if p is None and f is None and e is None:
            raise RuntimeError(f"at least one of path, file, and extension must be set for rake: {t}")

        o = RakeFileMeta(t, d, s, path=p, file=f, ext=e, all=a)
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
                 ctx_group:int=None, key_group:int=None, val_group:int=None, ignorecase:bool=False):

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

        relpath = None
        offset = 0
        for m in self.pattern.findall(text):
            if isinstance(m, tuple):
                key = m[self.key_group] if self.key_group is not None else None
                val = m[self.val_group] if self.val_group is not None else None
                ctx = m[self.ctx_group] if self.ctx_group is not None else None
            else:
                key = None
                val = m if self.val_group is not None else None
                ctx = m if self.ctx_group is not None else None

            if relpath is None:
                relpath = self.relPath(context['basepath'], context['fullpath'])

            rm = RakeMatch(self,
                           file=relpath,
                           line=context['lineno'])

            key_off = 0
            if key is not None:
                key_off = text.find(key, offset)
                key_len = len(key)
                rm.set_key(key, key_off, key_len)

            val_off = 0
            if val is not None:
                val_off = text.find(val, offset)
                val_len = len(val)
                rm.set_value(val, val_off, val_len)

            ctx_off = 0
            if ctx is not None:
                ctx_off = text.find(ctx, offset)
                ctx_len = len(ctx)
                rm.set_context(ctx, ctx_off, ctx_len)

            offset = max(ctx_off, val_off) + 1

            rm.match_groups = m  # save the groups for later use in filters
            rm.full_context = context  # save the context for later use in filters
            mset.append(rm)

        results = filter(self.filter, mset)
        return list(results)

    def filter(self, m:RakeMatch):
        '''
        Check filters against given match.  A single positive match is enough
        to return False (indicating result should be filtered).

        Returns False if result should be filtered.
        '''

        for f in self.filters:
            if not f.match(m): return False

        return True

    @staticmethod
    def load(config):
        '''
        Create a RakeFileMeta given a Rake configuration from datarake.yaml
        '''

        n = config.get('name', "<-None->")
        p = config.get('pattern', None)
        d = config.get('description', "<-None->")
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
            raise RuntimeError("filters must be a list for Rake {n}")

        for f in filters:
            fo = RakeFilter.load(f)
            o.addFilter(fo)

        return o

class RakeContextPattern(Rake):
    '''
    This rake binds patterns to file contexts (extension).

    Individual rakes (patterns) will be instantiated as RakePatterns, but will be applied by extension.
    '''

    def __init__(self, ptype:str, pdesc:str, severity:str):

        Rake.__init__(self, ptype, pdesc, severity)
        return

    def match(self, context:dict, text:str):
        mset = []

        results = filter(self.filter, mset)
        return list(results)

    def addContext(self, ctx:str, rp:RakePattern):
        '''
        Add a RakePattern (ro) to the given context (ctx)
        '''

    @staticmethod
    def load(config):
        '''
        Create a RakeFileMeta given a Rake configuration from datarake.yaml
        '''

        n = config.get('name', "<-None->")
        d = config.get('description', "<-None->")
        s = config.get('severity', "LOW")

        rc = RakeContextPattern(n, d, s)

        for c in config.get("contexts", []):
            ctx = c.get('context', None)

            if not isinstance(ctx, list):
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
                raise RuntimeError("filters must be a list for Rake {n}")

            for f in filters:
                fo = RakeFilter.load(f)
                o.addFilter(fo)

            for x in ctx:
                rc.addContext(x, o)

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

    def __init__(self, domain:str=None, **kwargs):
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

    def filter(self, m:RakeMatch):
        fqdn = m.value
        if not RakeHostname.isValidHostname(fqdn):
            return False
        
        return super().filter(m)


class RakeEmail(RakePattern):
    '''
    Detect email addresses.  If domain is not None, the domain associated with
    the email account must match the specified domain.
    '''

    def __init__(self, domain:str=None, **kwargs):
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

    def filter(self, m:RakeMatch):
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

    def match(self, context:dict, text:str):
        mset = []
        for match in self.pattern.findall(text):
            # we may or may not have something juicy... let's attempt to
            # decode it and see if it checks out!
            try:
                encoded = match[1]  # skip leading "Basic " label
                val = base64.b64decode(encoded, validate=True).decode(self.encoding).strip()
            except Exception:
                # not base64 means this probably isn't Basic auth
                continue

            # does it smell like basic auth?  (user:pass)
            if not val.isprintable() or val.find(":") < 1:
                continue

            m = RakeMatch(self,
                          file=self.relPath(context['basepath'], context['fullpath']),
                          line=context['lineno'])

            m.set_context(match[0], offset=0, length=len(match[0]))
            m.set_value(value=match[1], offset=6, length=len(match[1]))
            mset.append(m)

        return filter(self.filter, mset)


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
                                  ignorecase=False, **kwargs)

        self.encoding = encoding
        return

    def match(self, context:dict, text:str):
        mset = []
        relfile = None
        for m in self.pattern.findall(text):
            # we may or may not have something juicy... let's attempt to
            # decode it and see if it checks out!
            if self.encoding is not None:
                try:
                    # all we care is that the base64 and JSON decode works on
                    # the first two parts of the token.  If either fail, this
                    # isn't JWT.

                    for st in [ m[1], m[2] ]:                      # st is subtoken
                        npad = len(st) % 4                         # npad is num padding (req'd)
                        st = st + ("=" * npad)
                        td = base64.b64decode(st).decode('utf-8')  # td is token data
                        json.loads(td)

                except Exception:
                    continue

            token = m[0]

            if relfile is None:
                relfile = self.relPath(context['basepath'], context['fullpath'])

            rm = RakeMatch(self,
                           file=relfile,
                           line=context['lineno'])

            rm.set_value(value=token, length=len(token), offset=text.find(token))
            mset.append(rm)

        return filter(self.filter, mset)

def SentinalRake(Rake):
    '''
    A SentinalRake requires two passes of the data.  In the first pass, it
    looks for a sentinal pattern.  If found, a second pass is made through
    the file looking for the target pattern.  This is useful where the
    presence of two patterns correlates, but either pattern alone is not of
    much interest.  Ex:  a cloud provider's identity and a secret key.
    '''
    def __init__(self, pattern:str, ptype:str, pdesc:str, severity:str,
                       ctx_group:int=None, val_group:int=None, ignorecase:bool=True):
        return