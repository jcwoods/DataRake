import binascii
import math
import re
import sys

from base64 import b64decode
from collections import Counter
from functools import lru_cache


class EntropyParser(object):
    parser = None

    def __init__(self, threshold:float=0.9):
        self.threshold = threshold
        return

    def to_seq(self, txt:str):
        '''
        Accepts a character string and decodes it to an iterable suitable
        for use in an entropy calculation.  If the value cannot be decoded,
        None is returned.

        Hex and B64 returns a byte array.  Txt returns a string (which is
        iterable).
        '''

        return list(txt)

    def parse_line(self, txt:str):
        '''
        Given a line of text, returns tuples of possible patterns which might
        be processed by the current processor.  If no patterns are recognized,
        an empty list is returned.
        '''

        raise RuntimeError("pure abstract method called")

    def filter(self, s:str):
        return False

    @staticmethod
    @lru_cache(maxsize=128)
    def max_entropy(ls:int):
        '''
        Returns the maximum entropy (measured in bits) for a sequence of given
        length 'ls'.
        '''
        fls = float(ls)
        x = 1/fls * math.log(1/fls, 2)
        return -(x * fls)

    @staticmethod
    #@lru_cache(maxsize=8192)
    def entropy(seq:list):
        p = Counter(seq)
        ls = float(len(seq))
        return -sum( count/ls * math.log(count/ls, 2) for count in p.values())

    def do_line(self, txt:str):
        '''
        A generic implementation that should work with most parsers.  Override
        parse_line and to_seq as needed.
        '''

        toks = self.parse_line(txt)
        if len(toks) == 0:
            return None

        # seqs[] will contain tuples of "token" and "sequence" objects
        seqs = list()
        for tok in toks:
            s = self.to_seq(tok)
            if s is None:
                 continue

            e = EntropyParser.entropy(s)
            min_e = EntropyParser.max_entropy(len(s)) * self.threshold
            if e < min_e:
                continue

            seqs.append( (self.parser, e, tok) )

        if len(seqs) == 0: return None
        return seqs


class HexEntropyParser(EntropyParser):
    '''
    Measure entropy of hex-encoded data, not the plaintext encoding. As an
    example, let's consider a hex-encoded key value:

        67fdf820c65ce4d896d164903315e9e4

    Taken as plain text, the key is 32 characters long and has a maximum entropy
    value of 5.0 (2^5 == 32).  We can see that several characters in the string
    are repeated -- the '6' character is repeated four times, for instance.  The
    entropy for this string is actually 3.718.  For lack of a better term, I am
    going to call this the "apparent entropy".

    If we take this as the byte values encoded in the string, we get:

        [ 67, fd, f8, 20, c6, 5c, e4, d8, 96, d1, 64, 90, 33, 15, e9, e4 ]

    This SEQUENCE has a length of 16 and a maximum entropy of 4.0 (2^4 == 16).
    Only one byte in this sequence is repeated: 'e4'. There are fifteen unique
    values and one repeated value, resulting in a measured "true" entropy of
    3.875.

    Looking at the ratio of the measured "true" entropy (3.875) to the max
    entropy (4.0) of the encoded data tells a much different story than
    looking at the "apparent entropy" (3.718) compared to the max entropy of
    the string (5.0).
'''

    regex = re.compile(r'\b(0x)?([A-Fa-f0-9]{16,})\b')
    parser = "hex"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        return

    def to_seq(self, txt:str):
        if len(txt) % 2 != 0: return None
        try:
            ba = bytearray.fromhex(txt)
        except ValueError:
            return None

        return list(ba)

    def parse_line(self, txt:str):
        '''
        Find all candidate Hex-encoded strings in the supplied line of text.
        '''

        tuples = HexEntropyParser.regex.findall(txt)
        if len(tuples) == 0: return list()

        # Regex returns a two-part tuple.  We want the second.
        hits = list(map(lambda x: x[1], tuples))
        if len(hits) == 0: return list()

        # a valid hit here must by "full bytes" ()
        valid_hits = list(filter(lambda h: len(h) % 2 == 0, hits))
        return valid_hits


class B64EntropyParser(EntropyParser):

    regex = re.compile(r'(([A-Za-z0-9+/]{4}){3,}([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?)')
    parser = "b64"

    def __init__(self, min_length=9, **kwargs):
        super().__init__(**kwargs)
        self.min_length = min_length
        return

    def parse_line(self, txt:str):
        tuples = B64EntropyParser.regex.findall(txt)
        if len(tuples) == 0:
            return list()

        # removes matches from tuples
        hits = list(map(lambda x: x[0], tuples))

        # removes strings of invalid lengths
        hits = list(filter(lambda x: len(x) > 0 and len(x) % 4 == 0, hits))

        # removes strings with unlikely ucase/lcase/digits patterns
        hits = filter(self._isBase64, hits)

        return list(hits)

    @staticmethod
    def _isBase64(hit:str):
        # base64 patterns generate A LOT of false positives.  We'll attempt
        # to whittle them down here.
        #
        # Base64 can contain 4 classes of chars, but three of these are
        # common:  lower, upper, and digits.  Upper and lower should appear
        # (roughly) 26/64, or about 40%.  Digits should account for 10/64, or
        # about 15%.  Punctuation will be # 2/64, or about 3%.
        #
        # We want to reject strings which are more than 2x out of whack
        # (either low or high) on any of these counts.  If the string ends
        # with '=', we can be a little more sure that the text is b64, so
        # we can relax the limits to 3x.

        # TODO - a bayes filter could be very effective here (bigrams).

        # count number of uppercase, lowercase, and digits
        n_ucase = sum(map(lambda h: 1 if h.isupper() else 0, hit))
        n_lcase = sum(map(lambda h: 1 if h.islower() else 0, hit))
        n_digits = sum(map(lambda h: 1 if h.isdigit() else 0, hit))
        n_punct = sum(map(lambda h: 1 if h in ['+', '/' ] else 0, hit))

        # length of encoding (adjusted for trailing '=')
        lh = len(hit)
        m = 0.40
        ends_equal = False
        if hit[-1] == '=':       # trailing = ?
            m = 0.60
            ends_equal = True
            lh -= 1
            if hit[-2] == '=':   # are there two trailing == ?
                lh -= 1
                m = 0.75

        # These are the distributions we would normally expect to find chars
        # in base64:  upper and lowercase each at 26/64 (0.40625), digits at
        # 10/64 (0.15625), and punctuation at 2/64 (0.03125).  Normally, we
        # would "split" the range for +/-, but here we'll allow +/- the full
        # range to allow a more "relaxed" deviation.
        du = lh * m * 0.40625  # delta uppercase (+/- range)
        dl = lh * m * 0.40625  # delta lowercase (+/- range)
        dd = lh * m * 0.15625  # delta digits (+/- range)
        dp = lh * m * 0.03125  # delta punct (+/- range)

        # make sure we have a reasonable minimum of each class.  Is there at
        # least half of what we would expect to see?
        ucase = n_ucase > int(lh - d) and n_ucase <= int(lh + d)
        lcase = n_lcase > int(lh - d) and n_lcase <= int(lh + d)
        digits = n_digits > int(lh - d) and n_digits <= int(lh + d)

        # finally, do we keep the hit?
        keep = False
        if ends_equal:
            if (ucase and lcase) or \
               (ucase and digits) or \
               (lcase and digits): keep = True
        else:
            if ucase and lcase and digits: keep = True

        return keep

    def to_seq(self, txt:str):
        '''
        We read a string from our input file.  This string contains b64-encoded
        data, so we (attempt to) convert it to a sequence.

        This resulting byte array may contain UTF-encoded data, or it may be
        raw data.  Attempt to decode the byte array using common encodings.  If
        one of these attempts are successful, return a list of characters from
        the string.

        If we cannot successfully read the data as UTF, we will assume that it
        is a simple byte array (binary).

        If the b64decode fails (invalid encoding), returns None.
        '''

        try:
            ba = b64decode(txt, validate=True)
        except binascii.Error:
            return None

        # at this point, 'ba' holds the decoded data from the input text as a
        # byte array.  Can the bytes be interpreted as one of the common UTF-8
        # encoding standards?  If so, we will convert it to unicode code
        # points for entropy calculation.

        encodings = [ 'utf-8', 'utf-16' ]  # no one uses UTF-32, do they!?
        txt = None
        for e in encodings:
            try:
               txt = ba.decode(e)
               # successful decode, return the chars
               return list(txt)  if len(txt) >= self.min_length else None
            except UnicodeDecodeError:
                continue

        return list(ba) if len(ba) >= self.min_length else None


class TxtEntropyParser(EntropyParser):
    filters = [ re.compile(r'\.[a-z]{2,4}$', flags=re.I),  # file names?

                # var=1 , width="7
                re.compile(r'^[a-z]+="?\d{1,5}$', flags=re.I), # constant definitions, html attributes

                # ...</h1>...,  ...<h6>..., etc.
                re.compile(r'</?(h\d)>', flags=re.I),    # common html tags

                # a pair of parenthesis appear in the correct order, like:
                # ...function(...)... 
                re.compile(r'.+\[a-z0-9](.*\)', re.I),   # likely functions

                # ...function(param1,...
                re.compile(r'[a-z]\(.+,$', flags=re.I),    # partial function calls

                # likely arrays, a pair of square braces appear in the correct order, for example:
                # ...var[...]...
                re.compile(r'.+[a-z0-9]\[.*\]', flags=re.I) ]

    parser = "text"

    def __init__(self, minlength=8, upper=True, lower=True, numer=True, symbols=False, **kwargs):
        super().__init__(**kwargs)
        self.upper = upper
        self.lower = lower
        self.numer = numer
        self.symbols = symbols
        self.minlength = minlength
        self.maxlinelength = 512
        return

    def parse_line(self, txt:str):
        hits = []
        if len(txt) > self.maxlinelength: return hits

        tokens = txt.split()

        for tok in tokens:
            # minimum length?
            if len(tok) < self.minlength: continue

            # minimum (configured) content?
            hasUpper = False
            hasLower = False
            hasNumer = False
            hasSym = False

            for c in tok:
                if c.islower():
                    hasLower = True
                    continue

                if c.isupper():
                    hasUpper = True
                    continue

                if c.isnumeric():
                    hasNumer = True
                    continue

                if c.isprintable():
                    hasSym = True
                    continue

            if self.upper and not hasUpper: continue
            if self.lower and not hasLower: continue
            if self.numer and not hasNumer: continue
            if self.symbols and not hasSym: continue

            # remove "problem patterns" below.
            filtered = False
            for f in TxtEntropyParser.filters:
                if f.search(tok):
                    filtered = True

            if filtered: continue
            hits.append(tok)

        return hits


def main(argv):
    hexp = HexEntropyParser()
    b64p = B64EntropyParser()
    txtp = TxtEntropyParser()

    for f in argv[1:]:
        lno = 0
        #print(f"processing file: {f}")
        if f[-4:].lower() == ".pem": continue
        with open(f, encoding='utf-8') as fd:
            hits = None

            try:
                for line in fd:
                    lno += 1
                    line = line.strip()

                    #hits = hexp.do_line(line)
                    #if hits is not None:
                    #    print(f"hits: {hits} ({f}:{lno})")

                    #hits = b64p.do_line(line)
                    #if hits is not None:
                    #    print(f"hits: {hits} ({f}:{lno})")

                    hits = txtp.do_line(line)
                    if hits is not None:
                        for h in hits:
                            print("\t".join((h[0], str(h[1]), h[2], f, str(lno))))


            except UnicodeDecodeError:
                pass

        fd.close()

    return


if __name__ == "__main__":
    sys.exit(main(sys.argv))