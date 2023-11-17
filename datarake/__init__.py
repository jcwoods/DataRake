
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
- location data (file name, line number)
- matched vaule (sensitive data), including offset and length within line
- matched context, including offset and length within line

Assumptions:
- input files are UTF-8
- lines are delim by '\n'
- a pattern must exist entirely on a single line
- multiple matches of any type may occur within a line.  We want them all.

'''

# forward declaration to avoid undefined error
#class RakeMatch:
#    pass

from .common import RakeMatch
from .common import DirectoryWalker
from .common import RakeSet

from .rakes import Rake
from .rakes import RakeFileMeta
from .rakes import RakePattern
from .rakes import RakeContextPattern
from .rakes import RakeHostname
from .rakes import RakeEmail
from .rakes import RakeBasicAuth
from .rakes import RakeJWTAuth
