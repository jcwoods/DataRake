import base64
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
                    "filename": fnam }

        if ext is not None:
            context["filetype"] = ext

        return context

class FiletypeContextRake(object):

    def __init__(self, ptype, verbose=False):
        '''
        '''

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
        #print(str(context))
        #print(str(pattern))
        for m in pattern.findall(text):
            if isinstance(m, tuple):
                val = m[self.pos]
            else:
                val = m

            if self.verbose: print("+ hit:   " + str(val))
            mset.append((self.ptype, val))

        return mset


class RakeToken(FiletypeContextRake):

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


class RakePattern(object):
    '''
    This is a basic pattern.  It will be compiled into a regex.
    '''
    special = '.^$*?\{\}()[]\\\|'  # . ^ $ * + ? { } [ ] \ | ( )

    def __init__(self, pattern, ptype, pos=0, ignorecase=True, verbose=False):
        '''
        pattern is the pattern to be matched in the input text.
        ptype is the type of the pattern, supplied by the subclass.
        '''
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
        '''
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
            mset.append((self.ptype, val))

        return mset


class RakeSet(object):
    '''
    A wrapper (list) of RakePattern objects.  Each pattern in this list will
    be evaluated against each line of input text.
    '''
    def __init__(self, verbose=False, *args):
        self.rakes = list(args)
        self.verbose = verbose
        return

    def add(self, rake):
        self.rakes.append(rake)
        return

    def match(self, context, text:str):
        if self.verbose: print("Applying rakes to " + text)

        matches = []
        for rake in self.rakes:
            if self.verbose: print("* applying {}".format(rake.pattern))
            mset = rake.match(context, text)
            for m in mset:
                matches.append(m)

        return matches


class RakeMatch(object):
    '''
    Metadata used along with matches and match sets recording where the match
    came from.  Offset will be measured in characters, not bytes (for UTF-8).
    An offset of 1 is the first column of the line.
    '''

    def __init__(self, file:str = None, line:int = 0, hit = None):
        self.file = file
        self.line = line
        self.hit = hit
        return

    def __str__(self):
        return "|".join((self.file, str(self.line), self.hit[0], self.hit[1]))


class RakeEntropy(object):
    '''
    Considering all substrings of length 'n' of an input string 's', returns
    the greatest Shannon entropy.  By default, substrings of length 16 will
    be generated.

    If 'threshold' is set to a value greater than 0, the first substring
    achieving an entropy score greater than this value will cause the routine
    to immediately terminate.  This is useful if you know you're looking for
    something with an entropy higher than 4.0 (key material?), but you really
    don't care how much higher.

    For reference, the greates entropy which can be generated by a string of
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

    def __init__(self, n:int = 16, threshold:float=3.70, verbose=False):
        self.ptype = 'entropy'
        self.threshold = threshold
        self.n = n
        self.fn = float(n)
        self.verbose = verbose

        return

    def match(self, context, s):
        for subc in [ Counter(s[i:i+self.n]) for i in range(len(s) - self.n + 1) ]:
            e = -sum( count/self.fn * math.log(count/self.fn, 2) for count in subc.values())
            if self.threshold > 0 and e >= self.threshold:
                return [(self.ptype, s)]

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
    def __init__(self, domain = None, **kwargs):
        if domain is not None:
            d = RakePattern.escapeLiteralString(domain)
            r = r'([a-zA-Z1-9_.\-]+@' + d + r')'
        else:
            r = r'([a-zA-Z0-9_.\-]+@[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+)'
        RakePattern.__init__(self, r, 'email', **kwargs)
        return


class RakeKeyValue(RakePattern):
    '''
    Find labelled key/value pair, such as:
        key: value
        key = value
    '''
    def __init__(self, kval, n = 1, **kwargs):
        kv = RakePattern.escapeLiteralString(kval)
        kvp = r'(' + kv + r'\s*[:=]\s*(\S+))'
        RakePattern.__init__(self, kvp, 'keyvalue:{}'.format(kval), pos=1, **kwargs)
        return


class RakePrivateKey(RakePattern):
    '''
    Find PEM headers for private key files (SSH, X.509, etc).  One of:
        -----BEGIN PRIVATE KEY-----
        -----BEGIN RSA PRIVATE KEY-----
        -----BEGIN DSA PRIVATE KEY-----
        -----BEGIN EC PRIVATE KEY-----
        -----BEGIN OPENSSH PRIVATE KEY-----
    '''
    def __init__(self, **kwargs):
        kp = r'^-----BEGIN ((RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----$'
        RakePattern.__init__(self, kp, 'private key', ignorecase=False, **kwargs)
        return


class RakeBearerAuth(RakePattern):
    '''
    Find likely Bearer auth tokens (as used in HTTP headers).  Eg,

        Authorization: Bearer 986272DF-F26E-4A47-A1E4-B0FC0024A3EE
    '''

    def __init__(self, **kwargs):
        kp = r'(Bearer [^ ]{8,})$'
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
    def __init__(self, encoding='utf-8', **kwargs):
        kp = r'(Basic [A-Za-z0-9+/]{16,}={0,2})$'
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
                except:
                    continue

            if not val.isprintable() or val.find(":") < 1:
                continue

            mset.append((self.ptype, " ".join(("Basic", val))))
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
                except:
                    continue

            if not val.isprintable(): continue
            mset.append((self.ptype, val))

        return mset


def RakeFile(context:dict, rs:RakeSet, blacklist:list=None, verbose=False):
    '''
    Applies a set of rakes (rs) to the file described in context.

    If the file ends with any of the values listed in 'blacklist', it will be
    skipped.  Matches are case insensitive.

    A list of hits are returned.
    '''

    if blacklist is None:
        blacklist = [".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                     ".tiff", ".zip", ".doc", ".docx", ".xls", ".xlsx",
                     ".pdf", ".tgz", ".gz", ".tar.gz",
                     ".jar", ".war", "ear", ".class" ]

    path = context.get("path", None)
    filename = context.get("filename", None)

    findings = list()

    if path is None or filename is None:
        # log an error here
        return findings

    fullpath = context.get("fullpath", None)
    if fullpath is None:
        fullpath = os.path.join(path, filename)

    for ext in blacklist:
        if ext == filename[-len(ext):].lower():
            return findings

    try:
        fd = open(fullpath, encoding="utf-8")
    except FileNotFoundError:
        return findings

    try:
        lineno = 1
        for line in fd:
            if verbose: print("text:      " + line.strip())

            hits = rs.match(context, line)
            if len(hits) > 0:
                taggedhits = list()
                for h in hits:
                    taggedhits.append(RakeMatch(file=fullpath, line=lineno, hit=h))

                findings.extend(taggedhits)

            if verbose: print("")
            lineno += 1
    except UnicodeDecodeError:
        if verbose: print("* Invalid file content: " + filename)

    fd.close()
    return findings


def main(args):

    if len(args) not in [2, 3]:
        raise RuntimeError("Invalid command line arguments.")

    pathArgN = 1  # the index (n) of the path to be scanned in argv
    rs = RakeSet()

    if (len(args) == 3):
        rs.add(RakeHostname(domain = args[1]))
        rs.add(RakeEmail(domain = args[1]))
        pathArgN = 2    # don't scan first arg, do the second!

    #rs.add(RakeEntropy(n=32, threshold=4.875))
    #rs.add(RakeBase64(encoding='utf-8'))

    rs.add(RakeURL())
    rs.add(RakePassword())
    rs.add(RakeToken())
    rs.add(RakeAWSHMACAuth())
    rs.add(RakeBasicAuth())
    rs.add(RakeBearerAuth())
    rs.add(RakePrivateKey())

    dw = DirectoryWalker(path=args[pathArgN])
    for context in dw:
        findings = RakeFile(context, rs, verbose=False)
        for f in findings:
            print(f)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
