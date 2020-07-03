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
            blacklist = [ '.svn', '.git' ]

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

        return (path, fnam, ext)

class RakePattern(object):
    '''
    This is a basic pattern.  It will be compiled into a regex.
    '''
    special = '.^$*?\{\}()[]\\\|'  # . ^ $ * + ? { } [ ] \ | ( )

    def __init__(self, pattern, ptype, pos = 0, ignorecase=True, verbose=False):
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

    def match(self, text, verbose=False):
        mset = []
        if verbose:
            print("* ptype:   " + self.ptype)
            print("* pattern: " + str(self.pattern))
            print("* text: " + str(text))

        for m in self.pattern.findall(text):
            if isinstance(m, tuple):
                val = m[self.pos]
            else:
                val = m

            if verbose: print("+ hit:   " + str(val))
            mset.append((self.ptype, val))

        return mset


class RakeSet(object):
    '''
    A wrapper (list) of RakePattern objects.  Each pattern in this list will
    be evaluated against each line of input text.
    '''
    def __init__(self, *args):
        self.rakes = list(args)
        return

    def add(self, rake):
        self.rakes.append(rake)
        return

    def match(self, text:str, verbose=False):
        if verbose: print("Applying rakes to " + text)

        matches = []
        for rake in self.rakes:
            if verbose: print("* applying {}".format(rake.pattern))
            mset = rake.match(text, verbose=verbose)
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

    def __init__(self, n:int = 16, threshold:float=3.70):
        self.ptype = 'entropy'
        self.threshold = threshold
        self.n = n
        self.fn = float(n)

        return

    def match(self, s, verbose=False):
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

    def __init__(self, domain = None):
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

        RakePattern.__init__(self, r, 'hostname')
        return

class RakeURL(RakePattern):
    def __init__(self, credentials=True):
        '''
        a very crude pattern to match URLs, roughly of the pattern:
            xxx://user:pass@xxx.xxx:ppp/zzz+
        '''
        if credentials:
            r = r'\b([a-z]{2,6}://[a-z0-9%+/=\-]+:[a-z0-9%+/=\-]+@[A-Z0-9_-]+(\.[A-Z0-9_-]+)+(:\d{1,5})?(/(\S*)?)?)\b'
        else:
            r = r'\b([a-z]{2,6}://[a-z0-9_-]+(\.[a-z0-9_-]+)+(:\d{1,5})?(/(\S*)?)?)\b'

        #if domain is None:
        #    r = r'\b([A-Z]{2,6}://([A-Z0-9%@+/=\-]+:[A-Z0-9%@+/=\-]+)?[A-Z0-9_-]+(\.[A-Z0-9_-]+)+(:\d+)?(/(\S*)?)?)\b'
        #else:
        #    d = RakePattern.escapeLiteralString(domain)
        #    r = r'\b([A-Z]{2,6}://([A-Z0-9%@+/=\-]+:[A-Z0-9%@+/=\-]+)?([A-Z0-9_-]+\.)*' + d + r'(:\d+)?(/(\S*)?)?)\b'

        RakePattern.__init__(self, r, 'url')
        return

class RakePassword(RakePattern):
    '''
    A basic password matching pattern.
    '''

    def __init__(self, minlength:int=6):
        r = r"(([\"']?)pass(w(ord)?)?(\2)[ \t]*[=:][ \t]*(['\"]?)[\x21\x23-\x26\x28-\x7e]{"+str(minlength)+",}(\6))"
        RakePattern.__init__(self, r, "password")
        return

class RakeToken(RakePattern):
    '''
    A basic auth token matching pattern.
    '''

    def __init__(self, minlength:int=6):
        r = r"([\"']?)(auth)?tok(en)?(\1)[ \t]*[=:][ \t]*(['\"]?)[\x21\x23-\x26\x28-\x7e]{"+str(minlength)+",}(\5)"
        RakePattern.__init__(self, r, "token")
        return

class RakeEmail(RakePattern):
    def __init__(self, domain = None):
        if domain is not None:
            d = RakePattern.escapeLiteralString(domain)
            r = r'([a-zA-Z1-9_.\-]+@' + d + r')'
        else:
            r = r'([a-zA-Z0-9_.\-]+@[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+)'
        RakePattern.__init__(self, r, 'email')
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
        RakePattern.__init__(self, kp, 'privatekey', ignorecase=False, **kwargs)
        return


class RakeBase64(RakePattern):
    def __init__(self, minlength:int=16, encoding:str = 'utf-8'):
        '''
        a pattern to match Base64 encoded values.
        minlength will set the minimum length of the matched string.
        encoding will require that the data can be successfully read using the
          given coding.  If encoding is None, no attempt to decode the data will be made.
        '''
        r = r'\b([A-Za-z0-9+/]{' + str(minlength) + r',}={0,2})\b'

        RakePattern.__init__(self, r, 'base64')
        self.encoding = encoding
        return

    def match(self, text:str, verbose:bool=False):
        mset = []
        if verbose:
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


def RakeFile(path:str, filename:str, filetype:str, rs:RakeSet, verbose=False):
    findings = list()

    fullpath = os.path.join(path, filename)

    try:
        fd = open(fullpath, encoding="utf-8")
    except FileNotFoundError:
        return []

    try:
        lineno = 1
        for line in fd:
            if verbose: print("text:      " + line.strip())

            hits = rs.match(line, verbose=verbose)
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

    if len(findings) > 0:
        for f in findings:
            print(str(f))

    return


def main(args):

    if len(args) != 2:
        raise RuntimeError("Invalid command line arguments.")

    rs = RakeSet()

    if (len(args) == 3):
        print("Adding domain checks")
        rs.add(RakeHostname(domain = args[1]))
        rs.add(RakeEmail(domain = args[1]))

    #rs.add(RakeEntropy(n=32, threshold=4.875))

    rs.add(RakeURL())
    rs.add(RakeBase64(encoding='utf-8'))
    rs.add(RakePassword())
    rs.add(RakeToken())
    rs.add(RakePrivateKey())

    n = 1
    if len(args) > 2: n = 2

    dw = DirectoryWalker(path=args[1])
    for f in dw:
        RakeFile(f[0], f[1], f[2], rs, verbose=False)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
