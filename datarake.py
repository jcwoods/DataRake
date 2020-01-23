import re
import sys

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

class RakePattern(object):
    '''
    This is a basic pattern.  It will be compiled into a regex.
    '''
    special = '.^$*?\{\}()[]\\\|'  # . ^ $ * + ? { } [ ] \ | ( )

    def __init__(self, pattern, ptype, pos = 0, verbose=False):
        '''
        pattern is the pattern to be matched in the input text.
        ptype is the type of the pattern, supplied by the subclass.
        '''
        if verbose: print(pattern)

        self.pattern = re.compile(pattern, flags=re.IGNORECASE)
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

    #taggedhits.append(RakeMatch(file=filename, line=lineno, hit=h))
    def __init__(self, file:str = None, line:int = 0, hit = None):
        self.file = file
        self.line = line
        self.hit = hit
        return

    def __str__(self):
        #return "|".join((self.file, str(self.line), str(self.hit)))
        return "|".join((self.file, str(self.line), self.hit[0], self.hit[1]))


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
    def __init__(self, domain=None):
        '''
        a very crude pattern to match URLS, roughly of the pattern:
            xxx://xxx.xxx:ppp/zzz+
        '''
        if domain is None:
            r = r'\b([A-Z]{2,6}://([A-Z0-9%@+/=\-]+:[A-Z0-9%@+/=\-]+)?[A-Z0-9_-]+(\.[A-Z0-9_-]+)+(:\d+)?(/(\S*)?)?)\b'
        else:
            d = RakePattern.escapeLiteralString(domain)
            r = r'\b([A-Z]{2,6}://([A-Z0-9%@+/=\-]+:[A-Z0-9%@+/=\-]+)?([A-Z0-9_-]+\.)*' + d + r'(:\d+)?(/(\S*)?)?)\b'

        RakePattern.__init__(self, r, 'url')
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


def RakeFile(filename:str, rs:RakeSet, verbose=False):
    findings = list()

    try:
        fd = open(filename, encoding="utf-8")
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
                    taggedhits.append(RakeMatch(file=filename, line=lineno, hit=h))

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

    if len(args) < 3:
        raise RuntimeError("Invalid command line arguments.")

    rs = RakeSet()
    rs.add(RakeHostname(domain = args[1]))
    rs.add(RakeEmail(domain = args[1]))
    rs.add(RakeKeyValue("username"))
    rs.add(RakeKeyValue("user"))
    rs.add(RakeKeyValue("uname"))
    rs.add(RakeKeyValue("un"))
    rs.add(RakeKeyValue("password"))
    rs.add(RakeKeyValue("pass"))
    rs.add(RakeKeyValue("pw"))
    rs.add(RakeKeyValue("authtok"))
    rs.add(RakeKeyValue("token"))
    rs.add(RakeKeyValue("tok"))
    rs.add(RakeURL(domain = args[1]))

    for f in args[2:]:
        RakeFile(f, rs, verbose=False)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
