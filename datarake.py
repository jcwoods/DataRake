import argparse
import base64
import json
import math
import os
import re
import sys

from collections import Counter

'''
A forensics tool which scans a directory structure for elements such as:

- host names (matching specified domains)
- full URLs/URIs
- email addresses
- keywords (eg, "username", "pw", "authTok", etc)
- key patterns (eg, "Basic <base64 encoded data>", URI encodings, etc.)

We should be allowed to limit searches of files either by:

- whitelist (only authorized file extensions)
- blacklist (exclude unauthorized file extensions)

Eventually, we should look into decoding base64 or URI encoded data and
returning the content rather than the encoded data.

Report output should include:

- type of match
- matching text
- location data (file, line, offset)

Assumptions:
- input files are UTF-8
- lines are delim by '\n'
- a pattern must exist entirely on a single line
- multiple matches of any type may occur within a line.  We want them all.

'''

class DirectoryWalker:

    def __init__(self, path=".", blacklist = None):
        '''
        path is the path to be traversed.

        blacklist is a list of DIRECTORIES to be excluded.  By default, source
        control directories (.svn, .git) will be used.
        '''

        if blacklist is None:
            blacklist = [ '.svn', '.git', '__pycache__' ]

        self.blacklist = blacklist
        self.path = path
        return

    def __iter__(self):
        self.w = os.walk(self.path)

        self.t = None    # current tuple (from os.walk).
        self.i = 0       # index into file list
        return self

    def __next__(self):

        while self.t is None:
            t = self.w.__next__()

            # apply blacklist to directories prior to recursion
            t[1][:] = [d for d in t[1] if d not in self.blacklist]

            if len(t[2]) == 0:
                continue

            self.i = 0
            self.t = t

        t = self.t
        i = self.i

        self.i += 1
        if self.i >= len(self.t[2]):
            self.t = None

        path = t[0]
        fnam = t[2][i]

        # determine file extension, if any
        parts = fnam.split(".")
        ext = parts[-1] if len(parts) > 1 else None

        context = { "path": path,
                    "filename": fnam,
                    "fullpath": os.path.join(path, fnam) }

        if ext is not None:
            context["filetype"] = ext

        return context

class Rake(object):
    '''
    A Rake is an abstract "issue finder".  Its subclasses do all of the real
    work.  When applied or executed, it creates RakeMatch objects.  Rake
    objects are grouped in RakeSet collections when many Rakes will be
    applied repeatedly.
    '''

    def __init__(self, name = None, part = 'content'):
        self.name = name
        self.part = part  # content, filemeta, etc.


class RakeFileMeta(Rake):
    '''
    Creates RakeMatch based on file metadata (name, path, extension) rather
    than content.

    If self.all_required is set to true, all patterns which have been
    defined MUST return true.  Otherwise, we will return a positive
    result when the first match is made.
    '''

    def __init__(self, ptype, path=None, file=None, ext=None, all=True, verbose=False):
        Rake.__init__(self, name=self.__class__.__name__, part='filemeta')
        self.ptype = ptype
        self.path_pattern = None if path is None else re.compile(path)
        self.file_pattern = None if file is None else re.compile(file)
        self.ext_pattern = None if ext is None else re.compile(ext)
        self.all_required = all
        self.verbose = verbose
        return

    def match(self, context):
        path = context.get('path', None)
        fnam = context.get('filename', None)
        ext = context.get('filetype', None)
        full = context.get('fullpath', None)

        # create the match up front, just in case!
        m = RakeMatch(file=full, line=None, label=self.ptype, hit=None)

        if self.path_pattern is not None:
            if path is None: return False
            if not self.path_pattern.match(path): return False
            if not self.all_required: return m

        if self.file_pattern is not None:
            if fnam is None: return False
            if not self.file_pattern.match(fnam): return False
            if not self.all_required: return m

        if self.ext_pattern is not None:
            if ext is None: return False
            if not self.ext_pattern.match(ext): return False
            if not self.all_required: return m

        return m


class RakeSSHIdentity(RakeFileMeta):
    '''
    SSH identity files (eg, "private keys")
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'ssh identity file', file=r"^id_(r|(ec)?d)sa$")
        return


class RakeNetrc(RakeFileMeta):
    '''
    Network credential storage.
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'netrc file', file=r"^.?netrc$")
        return

class RakePKIKeyFiles(RakeFileMeta):
    '''
    Files often related with PKI/X509 keys.
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'x509 key file', ext=r"^(pem|pfx|p12|p7b|key)$")
        return

class RakeKeystoreFiles(RakeFileMeta):
    '''
    Files often related with Java keystores.
    TODO:  test default/simple passwords (changeit, changeme, password)
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'java keystore', 
                              file=r"^keystore$",
                              ext=r"^(jks|keystore)$",
                              all=False)
        return

class RakeHtpasswdFiles(RakeFileMeta):
    '''
    Apache htpasswd files.
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'apache htpasswd', file=r"^\.?htpasswd$")
        return

class FiletypeContextRake(Rake):
    '''
    Manages a set of Rakes, applying each based on file type (extension).
    '''

    def __init__(self, ptype, verbose=False):
        Rake.__init__(self, name=self.__class__.__name__, part='content')
        self.ptype = ptype        # description of this rake
        self.patterns = dict()
        self.verbose = verbose
        return

    def addContext(self, filetype, pattern, pos=0):
        self.patterns[filetype] = pattern
        self.pos = pos
        return

    def match(self, context, text):
        filetype = context.get("filetype", None)

        pattern = None
        if filetype is not None:
            filetype = filetype.lower()
            pattern = self.patterns.get(filetype, None)

        if pattern is None: pattern = self.patterns[None]

        mset = []

        for m in pattern.findall(text):
            if isinstance(m, tuple):
                val = m[self.pos]
            else:
                val = m

            if self.verbose: print("+ hit:   " + str(val))
            mset.append(RakeMatch(file=context['fullpath'],
                                  line=context['lineno'],
                                  label=self.ptype, 
                                  hit=val))

        return mset


class RakeToken(FiletypeContextRake):
    '''
    Detect tokens embedded in code or configurations.  This is context
    sensitive (based on file type).
    '''

    def __init__(self, minlength:int=6, **kwargs):
        FiletypeContextRake.__init__(self, 'token', **kwargs)
        self.minlength = minlength

        # add the default pattern (no other match)
        r = r"(([\"']?)(auth)?tok(en)?(\2)[ \t]*[=:][ \t]*(['\"]?)[\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",}(\6))"
        self.addContext(None, re.compile(r))

        # c, c++, java
        r = r'((auth)?tok(en)?[ \t]*=[ \t]*"[\x21\x23-\x26\x28-\x7e]{' + str(minlength) + r',}")'
        cre = re.compile(r, flags = re.IGNORECASE)
        self.addContext("c", cre)
        self.addContext("h", cre)
        self.addContext("cc", cre)
        self.addContext("cpp", cre)
        self.addContext("hpp", cre)
        self.addContext("java", cre)

        # js, py
        r = r"((auth)?tok(en)?[ \t]*=[ \t]*(['\"])[\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",}(\4))"
        self.addContext(None, re.compile(r))

        # yaml, yml
        r = r"((auth)?tok(en)?[ \t]*:[ \t]*(['\"]?)[\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",}(\4))"
        cre = re.compile(r, flags = re.IGNORECASE)
        self.addContext("yaml", cre)
        self.addContext("yml", cre)

        # shell, ini
        r = r"((auth)?tok(en)?[ \t]*=[ \t]*(['\"]?)[^\$][\x21\x23-\x26\x28-\x7e]{" + str(minlength-1) + r",}(\4))"
        cre = re.compile(r, flags = re.IGNORECASE)
        self.addContext("sh", cre)
        self.addContext("ini", cre)

        return


class RakePassword(FiletypeContextRake):
    '''
    Detect passwords embedded in code or configurations.  This is context
    sensitive (based on file type).
    '''

    def __init__(self, minlength=6, **kwargs):
        FiletypeContextRake.__init__(self, 'password', **kwargs)
        self.minlength = minlength

        # add the default pattern (no other match)
        r = r"(([\"']?)pass(w(ord)?)?(\2)[ \t]*[=:][ \t]*(['\"]?)[\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",}(\6))"
        self.addContext(None, re.compile(r))

        # c, c++, java
        r = r'(pass(w(ord)?)?[ \t]*=[ \t]*"[\x21\x23-\x26\x28-\x7e]{' + str(minlength) + r',}")'
        cre = re.compile(r, flags = re.IGNORECASE)
        self.addContext("c", cre)
        self.addContext("h", cre)
        self.addContext("cc", cre)
        self.addContext("cpp", cre)
        self.addContext("hpp", cre)
        self.addContext("java", cre)

        # js, py
        r = r"(pass(w(ord)?)?[ \t]*=[ \t]*(['\"])[\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",}(\4))"
        self.addContext(None, re.compile(r))

        # yaml, yml
        r = r"(pass(w(ord)?)?[ \t]*:[ \t]*(['\"]?)[\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",}(\4))"
        cre = re.compile(r, flags = re.IGNORECASE)
        self.addContext("yaml", cre)
        self.addContext("yml", cre)

        # shell, ini
        r = r"(pass(w(ord)?)?[ \t]*=[ \t]*(['\"]?)[^\$][\x21\x23-\x26\x28-\x7e]{" + str(minlength-1) + r",}(\4))"
        cre = re.compile(r, flags = re.IGNORECASE)
        self.addContext("sh", cre)
        self.addContext("ini", cre)

        return


class RakePattern(Rake):
    '''
    This is a basic pattern.  It will be compiled into a regex.
    '''
    special = r'.^$*?{}()[]|\\'  # . ^ $ * + ? { } [ ] \ | ( )

    def __init__(self, pattern, ptype, pos=0, ignorecase=True, verbose=False):
        '''
        pattern is the pattern to be matched in the input text.
        ptype is the type of the pattern, supplied by the subclass.
        '''
        Rake.__init__(self, name=self.__class__.__name__, part='content')

        if verbose: print(pattern)

        flags = 0
        if ignorecase:
            flags = re.IGNORECASE

        self.pattern = re.compile(pattern, flags=flags)
        self.ptype = ptype                 # pattern type
        self.pos = pos                     # position of match in output tuple
        self.verbose = verbose

        return

    @staticmethod
    def escapeLiteralString(s:str):
        r'''
        Escapes a string so that "special" regex characters are not
        accidentally passed through.  As an example, consider the difference
        of 'abc.com' and 'abc\.com' in a regex -- in the first, the '.' is
        a wildcard where in the second, it's a literal period.
        '''

        # a private function so we can use it in the comprehension ;)
        def escapeLiteral(c:str):
            if len(c) != 1:
                raise RuntimeError("One at a time, please!")

            if c in RakePattern.special:
                return '\\' + c

            return c

        return ''.join([escapeLiteral(c) for c in s])

    def match(self, context, text):
        mset = []
        if self.verbose:
            print("* ptype:   " + self.ptype)
            print("* pattern: " + str(self.pattern))
            print("* text: " + str(text))

        for m in self.pattern.findall(text):
            if isinstance(m, tuple):
                val = m[self.pos]
            else:
                val = m

            if self.verbose: print("+ hit:   " + str(val))
            mset.append(RakeMatch(file=context['fullpath'],
                                  line=context['lineno'],
                                  label=self.ptype,
                                  hit=val))

        return mset


class RakeSet(object):
    '''
    A wrapper (list) of RakePattern objects.  Each pattern in this list will
    be evaluated against each line of input text.
    '''
    def __init__(self, verbose=False, *args):
        self.content_rakes = list(args)
        self.meta_rakes = list()
        self.verbose = verbose
        return

    def add(self, rake):
        if rake.part == 'filemeta':
            self.meta_rakes.append(rake)
            return

        if rake.part == 'content':
            self.content_rakes.append(rake)
            return

        raise RuntimeError("Unknown rake type")

    def match_context(self, context):
        hits = list()
        for rake in self.meta_rakes:
            if rake.match(context):
                hits.append(RakeMatch(file=context['fullpath'],
                                      line=None,
                                      label=rake.ptype,
                                      hit=None))

        return hits

    def match_content(self, context, text:str):
        if self.verbose: print(f"Applying rakes to {text.rstrip()}")

        matches = []
        for rake in self.content_rakes:
            if self.verbose: print("* applying content rake {}".format(rake.pattern))
            mset = rake.match(context, text)
            for m in mset:
                matches.append(m)

        return matches
    
    def match(self, context, blacklist=None):
        if blacklist is None:
            blacklist = [".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                         ".tiff", ".zip", ".doc", ".docx", ".xls", ".xlsx",
                         ".pdf", ".tgz", ".gz", ".tar.gz",
                         ".jar", ".war", "ear", ".class" ]

        path = context.get("path", None)
        filename = context.get("filename", None)
        context['lineno'] = None

        findings = list()

        if path is None or filename is None:
            # log an error here
            return findings

        fullpath = context.get("fullpath", None)
        if fullpath is None:
            fullpath = os.path.join(path, filename)

        for ext in blacklist:
            # log message here
            if ext == filename[-len(ext):].lower():
                return findings

        context_hits = self.match_context(context)
        if len(context_hits) > 0: findings.extend(context_hits)

        try:
            fd = open(fullpath, encoding="utf-8")
        except FileNotFoundError:
            # log an error here
            return findings

        try:
            lineno = 1
            for line in fd:
                if self.verbose: print("text:      " + line.strip())

                context['lineno'] = lineno
                hits = self.match_content(context, line)
                findings.extend(hits)

                lineno += 1
        except UnicodeDecodeError:
            if self.verbose: print("* Invalid file content: " + filename)

        fd.close()
        return findings


class RakeMatch(object):
    '''
    Metadata used along with matches and match sets recording where the match
    came from.  Offset will be measured in characters, not bytes (for UTF-8).
    An offset of 1 is the first column of the line.
    '''

    def __init__(self, file:str = None, line:int = 0, label = None, hit = None):
        self.file = file
        self.line = line
        self.label = label
        self.hit = hit
        return

    def __str__(self):
        f = self.file if self.file is not None else ""
        ln = str(self.line) if self.line is not None else ""
        lb = self.label if self.label is not None else ""
        hit = self.hit if self.hit is not None else ""
        return "|".join((f, ln, lb, hit))


class RakeEntropy(Rake):
    '''
    Considering all substrings of length 'n' of an input string 's', returns
    the greatest Shannon entropy.  By default, substrings of length 16 will
    be generated.

    If 'threshold' is set to a value greater than 0, the first substring
    achieving an entropy score greater than this value will cause the routine
    to immediately terminate.  This is useful if you know you're looking for
    something with an entropy higher than 4.0 (key material?), but you really
    don't care how much higher.

    For reference, the greatest entropy which can be generated by a string of
    length 16 (all unique characters) is 4.0.  Both hexadecimal and base64
    encodings can fit this criteria, so 4.0 should be considered a maximum
    practical value for text files when using length 16.  A solid threshold
    for detecting data of this nature might be:

        - 3.70 (a single character repeated twice, everything else unique)
        - 3.75 (two characters, each repeated once, everything else unique)
        - 3.875 (a single character repeated once, everything else unique)

    This solution is based on the solution found on Rosetta Code:
        http://www.rosettacode.org/wiki/Entropy#Python:_More_succinct_version
    '''

    def __init__(self, n:int = 16, threshold:float=3.70, allow_space=False, verbose=False):
        Rake.__init__(self, name=self.__class__.__name__, part='content')
        self.ptype = 'high entropy'
        self.threshold = threshold
        self.n = n
        self.fn = float(n)
        self.allow_space = allow_space
        self.verbose = verbose

        return

    def match(self, context, s:str):
        for subc in [ Counter(s[i:i+self.n]) for i in range(len(s) - self.n + 1) ]:
            if not self.allow_space and ' ' in subc: continue
            e = -sum( count/self.fn * math.log(count/self.fn, 2) for count in subc.values())
            if self.threshold > 0 and e >= self.threshold:
                # only return first hit -- may be MANY!
                return RakeMatch(file=context['fullpath'],
                                 line=context['lineno'],
                                 label=self.ptype,
                                 hit=s.strip())

        return []


class RakeHostname(RakePattern):
    '''
    A RakeHostname acts as a 'root', meaning that it will match any valid hosts
    in the domain which share the root value.  For example, root="abc.com"
    will match not only "abc.com", but also "xyz.abc.com" and
    "foo.xyz.abc.com".

    A domain name may include A-Z, 0-9, and '-'.  The '-' may not appear at
    the beginning or end of the name.

    Any number of subdomains (equal to or beyond the depth inherent in the
    root) are supported.
    '''

    def __init__(self, domain=None, **kwargs):
        if domain is not None:
            d = RakePattern.escapeLiteralString(domain)
            r = r'\b(([a-z1-9\-]+\.)+' + d + r')\b'
        else:
            # going to make an arbitrary call here... domain must be 2 or
            # more "parts".  A name will need to be "host.d1.d2", We'll miss
            # things like "localhost.localdomain" but that should be
            # acceptable since we're not picking up 'a.b'-type symbols.  If
            # you don't like this, change the "{2,}" below to a simple "+".
            r = r'\b([a-z1-9\-]+(\.[a-z1-9\-]+){2,})\b'

        RakePattern.__init__(self, r, 'hostname', **kwargs)
        return


class RakeURL(RakePattern):
    '''
    Detect URLs.  If credentials is set to True (default), only URLs with
    embedded credentials will be reported.
    '''

    def __init__(self, credentials=True, **kwargs):
        '''
        a very crude pattern to match URLs, roughly of the pattern:
            xxx://user:pass@xxx.xxx:ppp/zzz+
        '''
        if credentials:
            r = r'\b([a-z]{2,6}://[a-z0-9%+/=\-]+:[a-z0-9%+/=\-]+@[A-Z0-9_-]+(\.[A-Z0-9_-]+)+(:\d{1,5})?(/(\S*)?)?)\b'
        else:
            r = r'\b([a-z]{2,6}://[a-z0-9_-]+(\.[a-z0-9_-]+)+(:\d{1,5})?(/(\S*)?)?)\b'

        RakePattern.__init__(self, r, 'auth url', **kwargs)
        return


class RakeEmail(RakePattern):
    '''
    Detect email addresses.  If domain is not None, the domain associated with
    the email account must match the specified domain.
    '''

    def __init__(self, domain = None, **kwargs):
        if domain is not None:
            d = RakePattern.escapeLiteralString(domain)
            r = r'([a-zA-Z1-9_.\-]+@' + d + r')'
        else:
            r = r'([a-zA-Z0-9_.\-]+@[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+)'

        RakePattern.__init__(self, r, 'email', **kwargs)
        return


class RakePrivateKey(RakePattern):
    '''
    Find PEM headers for private key files (SSH, X.509, etc).  One of:
        -----BEGIN PRIVATE KEY-----
        -----BEGIN RSA PRIVATE KEY-----
        -----BEGIN DSA PRIVATE KEY-----
        -----BEGIN EC PRIVATE KEY-----
        -----BEGIN OPENSSH PRIVATE KEY-----

        TODO: certificates are (often) base64-encoded DER.  Can we
              specifically detect a private key based on the DER?
    '''
    def __init__(self, **kwargs):
        kp = r'^(-----BEGIN (((RSA|DSA|EC|OPENSSH) )?(PRIVATE KEY)|CERTIFICATE)-----)$'
        RakePattern.__init__(self, kp, 'private key', ignorecase=False, **kwargs)
        return


class RakeBearerAuth(RakePattern):
    '''
    Find likely Bearer auth tokens (as used in HTTP headers).  Eg,

        Authorization: Bearer 986272DF-F26E-4A47-A1E4-B0FC0024A3EE
    '''

    def __init__(self, **kwargs):
        kp = r'(Bearer \S{8,})$'
        RakePattern.__init__(self, kp, 'auth bearer', ignorecase=False, **kwargs)
        return


class RakeBasicAuth(RakePattern):
    '''
    Find likely Basic auth tokens (as used in HTTP headers).  Eg,

        Authorization: Basic dXNlcjpwYXNzd29yZAo=

    Note that we use a minimum (practical) length of 16 when matching
    base64 data patterns.  If a potential base64-encoded value is found,
    we will decode it and make sure we have a ':' somewhere in the string
    as a minimal check.
    '''
    def __init__(self, minlen=16, encoding='utf-8', **kwargs):
        kp = r'(Basic [A-Za-z0-9+/]{'+ str(minlen) + r',}={0,2})$'
        RakePattern.__init__(self, kp, 'auth basic', ignorecase=False, **kwargs)
        self.encoding = encoding
        return

    def match(self, context, text:str):
        mset = []
        for m in self.pattern.findall(text):
            # we may or may not have something juicy... let's attempt to
            # decode it and see if it checks out!
            if self.encoding is not None:
                try:
                    encoded = m[6:]  # skip leading "Basic " label
                    val = base64.b64decode(encoded, validate=True).decode(self.encoding).strip()
                except Exception:
                    continue

            if not val.isprintable() or val.find(":") < 1:
                continue

            mset.append(RakeMatch(file=context['fullpath'],
                                  line=context['lineno'],
                                  label=self.ptype,
                                  hit=" ".join(("Basic", val))))
                                   
        return mset


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

    def __init__(self, encoding='utf-8', **kwargs):
        kp = r'\b([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/]{24,}={0,2})\b'
        RakePattern.__init__(self, kp, 'jwt token', ignorecase=False, **kwargs)
        self.encoding = encoding
        return

    def match(self, context, text:str):
        mset = []
        for m in self.pattern.findall(text):
            # we may or may not have something juicy... let's attempt to
            # decode it and see if it checks out!
            if self.encoding is not None:
                try:
                    t0 = base64.b64decode(m[0]).decode('utf-8')
                    t1 = base64.b64decode(m[1]).decode('utf-8')

                    # all we care is that the JSON decode works!  If it
                    # fails, this isn't JWT.
                    json.loads(t0)
                    json.loads(t1)
                except Exception:
                    continue

            token = ".".join((t0, t1))
            mset.append(RakeMatch(file=context['fullpath'],
                                  line=context['lineno'],
                                  label=self.ptype,
                                  hit=token))
        return mset


class RakeAWSHMACAuth(RakePattern):
    '''
    Find AWS4-HMAC-SHA256 authorization headers, eg:

        Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024

    See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
    '''
    def __init__(self, **kwargs):
        kp = r'(AWS-HMAC-SHA256 .+)$'
        RakePattern.__init__(self, kp, 'auth aws-hmac-sha256', ignorecase=False, **kwargs)
        return


class RakeBase64(RakePattern):
    def __init__(self, minlength:int=16, encoding:str = 'utf-8', **kwargs):
        '''
        a pattern to match Base64 encoded values.
        minlength will set the minimum length of the matched string.
        encoding will require that the data can be successfully read using the
          given coding.  If encoding is None, no attempt to decode the data will be made.
        '''
        r = r'\b([A-Za-z0-9+/]{' + str(minlength) + r',}={0,2})\b'

        RakePattern.__init__(self, r, 'base64', **kwargs)
        self.encoding = encoding
        return

    def match(self, context, text:str):
        mset = []
        if self.verbose:
            print("* ptype:   " + self.ptype)
            print("* pattern: " + str(self.pattern))

        for m in self.pattern.findall(text):
            # we may or may not have something juicy... let's attempt to
            # decode it and see if it checks out!
            if self.encoding is not None:
                try:
                    val = base64.b64decode(m, validate=True).decode(self.encoding).strip()
                except Exception:
                    continue

            if not val.isprintable(): continue
            mset.append(RakeMatch(file=context['fullpath'],
                                  line=context['lineno'],
                                  label=self.ptype,
                                  hit=val))

        return mset


class RakeSSHPass(RakePattern):
    '''
    Find uses of sshpass command (non-interactive ssh authentication).
    '''
    def __init__(self, **kwargs):
        kp = r'sshpass'
        RakePattern.__init__(self, kp, 'sshpass use', ignorecase=False, **kwargs)
        return


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
    parser.add_argument("-r", "--random", nargs="?", type=str, default=None,
                        metavar="ENTROPY", dest="entropy",
                        help="scan for high entropy strings.  ENTROPY is a threshold "
                             "formatted <bytes>:<entropy>, where <bytes> is the "
                             "length of substrings measured within the text and "
                             "<entropy> is the Shanon entropy score.  If you're "
                             "unsure what this means, start with ENTROPY set as "
                             "'32:4.875' and tune from there.")
    parser.add_argument("-b", "--base64", nargs="?", type=int, default=0,
                        help="scan for base64-encoded text with minimum encoded "
                             "length of BASE64.")
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

    parser.add_argument("PATH", default=None, nargs="+",
                        help="Path to be (recursively) searched.")

    return parser.parse_args(argv[1:])


def main(argv):
    cfg = parseCmdLine(argv)

    rs = RakeSet()

    if cfg.hostname:
        rs.add(RakeHostname(domain = cfg.domain))

    if cfg.email:
        rs.add(RakeEmail(domain = cfg.domain))

    if cfg.entropy is not None:
        try:
            l, t = cfg.entropy.split(":")
            blen = int(l)  # length of strings measured, in bytes
            es = float(t)  # minimum entropy score
        except ValueError as e:
            print(str(e))
            return 1

        rs.add(RakeEntropy(n=blen, threshold=es))

    if cfg.base64 > 0:
        blen = int(cfg.base64)
        rs.add(RakeBase64(minlength=blen, encoding='utf-8'))

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

    for d in cfg.PATH:
        dw = DirectoryWalker(d)
        for context in dw:
            findings = rs.match(context)
            for f in findings:
                print(f)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
