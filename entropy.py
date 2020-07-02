import math
import sys

from collections import Counter

def maxentropy(s:str, n:int=32, threshold:float=0.0):
    '''
    Considering all substrings of length 'n' of the input string 's', returns
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

    maxe = 0.0       # current max entropy
    lns = float(n)

    for subc in [ Counter(s[i:i+n]) for i in range(len(s) - n + 1) ]:
        e = -sum( count/lns * math.log(count/lns, 2) for count in subc.values())
        if e > maxe:
            if threshold > 0 and e >= threshold:
                return e

            maxe = e

    return maxe

def entropy(s:str):
    lns = float(len(s))
    subc = Counter(s)
    e = -sum( count/lns * math.log(count/lns, 2) for count in subc.values())
    return e


def main(argv):
    '''
    Returns the maximum entropy for any substring of length 16 within the
    command line argument.
    '''

    if len(argv) < 2:
        fd = sys.stdin
    else:
        fd = open(argv[1], encoding='utf-8')

    for line in fd:
        line = line.strip()
        print("{0:3.2f}: {1:s}".format(entropy(line), line))

    fd.close()
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
