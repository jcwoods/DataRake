import codecs
import hashlib
import os
import re
import sys

import chardet

from typing import Optional, Union
from collections import OrderedDict

# forward declaration so we can use type in Rake()
class RakeMatch:  # type: ignore
    pass

class DirectoryWalker:

    def __init__(self,
                 path:str=".",
                 blacklist:Optional[list]=None,
                 verbose:bool=False):

        '''
        path is the path to be traversed.

        blacklist is a list of DIRECTORIES to be excluded.  By default, source
        control directories (.svn, .git) will be used.
        '''

        if blacklist is None:
            blacklist = [ '.svn', '.git' ]

        self.blacklist = blacklist
        self.basepath = path
        self.verbose = verbose
        return

    def __iter__(self):
        self.w = os.walk(self.basepath)

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

        # TODO:  should this be a top-level RakeContext class?
        context = { "basepath": self.basepath,
                    "path": path,
                    "filename": fnam,
                    "fullpath": os.path.join(path, fnam),
                    "filetype": ext }

        # TODO:  possibly add size, mode, date to context.  They're not
        #        wanted/needed now, so we're not going to waste the iops.

        if self.verbose:
            print("* New context: " + str(context), file=sys.stderr)

        return context

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
    def relPath(basepath:str, fullpath:str) -> str:

        bplen = len(basepath)
        relpath = fullpath[bplen:]

        while relpath[0] == '/':
            relpath = relpath[1:]

        return  relpath

    def filter(self, m:RakeMatch) -> bool:
        '''
        A generic filter method.  If filter() returns false (eg, a match should
        be filtered), the result will not be added to the result set.

        Note that this is only a fail-safe, and that filters must be
        implemented within the context of a specific Rake-type.  The 'm'
        (match) parameter may be of different types and must be interpreted
        differently.
        '''
        return True

    def match(self, *args, **kwargs):
        '''
        Abstract method. Subclasses must implement one of two signatures:
          - filemeta rakes: match(context:dict) -> RakeMatch | None
          - content rakes:  match(context:dict, text:str) -> list[RakeMatch]
        The signature is selected by RakeSet based on self.part.
        '''
        raise NotImplementedError(
            f"Abstract method Rake.match() called on {self.__class__.__name__}")


class RakeMatch(object):
    '''
    Metadata used along with matches and match sets recording where the match
    came from.  Offset will be measured in characters, not bytes (for UTF-8).
    An offset of 1 is the first column of the line.
    '''

    # list of fields to be included (or not included) in output.  See
    fields = OrderedDict((('file', True),
                          ('line', True),
                          ('label', True),
                          ('severity', True),
                          ('description', True),
                          ('key_offset', False),
                          ('key_length', False),
                          ('key', False),
                          ('value_offset', True),
                          ('value_length', True),
                          ('value', True),
                          ('context_offset', True),
                          ('context_length', True),
                          ('context', True)))

    _secure = False            # if set, no "secrets" will be output
    _disable_context = False   # disable output of context, off, len
    _disable_value = False     # disable output of value, off, len
    _has_been_read = False

    def __init__(self,
                 rake:Rake,
                 file:Optional[str]=None,
                 line:Optional[int]=0): 

        self._label = rake.ptype
        self._description = rake.pdesc
        self._severity = rake.severity
        self._file = file
        self._line = line

        # these will be set by set_key(), set_value(), and set_context()
        self._key:Optional[tuple] = None
        self._value:Optional[tuple] = None
        self._context:Optional[tuple]= None

        return

    def secureContext(self) -> str:
        '''
        Produce a hash which can be use to (reasonably) securely track a
        secret if it moves within a file.  The hash will consist of the file
        name, a delimiter, and the literal value of the context.
        '''

        if self._context is None: return ""
        ctx = self._context[2]
        if ctx is None:
            return ""

        md5 = hashlib.md5()
        md5.update(self._file.encode('utf-8') if self._file is not None else b"")
        md5.update(bytes([0x00]))
        md5.update(ctx.encode('utf-8'))   # context value

        return md5.hexdigest()

    def __eq__(self, match) -> bool:
        if self._value is None and match._value is not None: return False
        if self._value is not None and match._value is None: return False
        if self._value is not None and match._value is not None:
            if self._value[0] != match._value[0]: return False  # offset
            # if self._value[1] != match._value[1]: return False  # length
            if self._value[2] != match._value[2]: return False  # value

        if self._context is None and match._context is not None: return False
        if self._context is not None and match._context is None: return False
        if self._context is not None and match._context is not None:
            if self._context[0] != match._context[0]: return False  # offset
            # if self._context[1] != match._context[1]: return False  # length
            if self._context[2] != match._context[2]: return False  # value

        if self._label != match._label: return False
        if self._description != match._description: return False
        if self._severity != match._severity: return False
        if self._file != match._file: return False
        if self._line != match._line: return False

        return True

    def __getattr__(self, k) -> Union[str, int, None]:
        RakeMatch._has_been_read = True

        if k in RakeMatch.fields.keys():

            if k == 'file': return self._file
            if k == 'line': return self._line
            if k == 'label': return self._label
            if k == 'severity': return self._severity
            if k == 'description': return self._description

            if k == 'value_offset':
                if self._value is None: return None
                return self._value[0]

            if k == 'value_length':
                if self._value is None: return None
                return self._value[1]

            if k == 'value':
                if RakeMatch._secure or self._value is None: return None
                return self._value[2]

            if k == 'context_offset':
                if self._context is None: return None
                return self._context[0]

            if k == 'context_length':
                if self._context is None: return None
                return self._context[1]

            if k == 'context':
                if self._context is None: return None
                if RakeMatch._secure: return self.secureContext()

                return self._context[2]

        if k == 'key':
            return self._key[2] if self._key is not None else None

        if k == 'external_id':
            # TODO - check that this is not being used!  Impl differs from secureContext(), above!
            i = "\u001e".join(map(lambda x: str(x), self.aslist()))  # \u001e is information (field) separator
            return hashlib.md5(i.encode('utf-8')).hexdigest()

        raise KeyError(f"Invalid key for RakeMatch: {k}")

    @staticmethod
    def csv_header() -> list:
        RakeMatch._has_been_read = True
        fields = []
        for f in RakeMatch.fields.keys():
            if RakeMatch.fields[f]:
                fields.append(f)

        return fields

    @staticmethod
    def set_secure() -> None:
        if RakeMatch._has_been_read:
            raise RuntimeError("must not modify RakeMatch structure after read")

        RakeMatch._secure = True
        RakeMatch.fields['context'] = True
        RakeMatch.fields['value'] = False
        return

    @staticmethod
    def disable_context() -> None:
        if RakeMatch._has_been_read:
            raise RuntimeError("must not modify RakeMatch structure after read")

        RakeMatch._disable_context = True
        RakeMatch.fields['context_offset'] = False
        RakeMatch.fields['context_length'] = False
        RakeMatch.fields['context'] = False
        return

    @staticmethod
    def disable_value() -> None:
        if RakeMatch._has_been_read:
            raise RuntimeError("must not modify RakeMatch structure after read")

        RakeMatch._disable_value = True
        RakeMatch.fields['value_offset'] = False
        RakeMatch.fields['value_length'] = False
        RakeMatch.fields['value'] = False
        return

    def set_key(self,
                key:str,
                offset:Optional[int]=None,
                length:Optional[int]=None) -> None:
        '''
        key differs from value and context in that it will (generally) not be
        output.  It is optional, and used (almost) exclusively for match
        filtering.
        '''

        if length is None:
            length = len(key)

        self._key = (offset, length, key)
        return

    def set_value(self,
                  value:str,
                  offset:Optional[int]=None,
                  length:Optional[int]=None) -> None:

        if length is None:
            length = len(value)
        else:
            self._length = length

        self._value = (offset, length, value)
        return

    def set_context(self,
                    value:str,
                    offset:Optional[int]=None,
                    length:Optional[int]=None):

        if length is None:
            self._length = len(value)
        else:
            self._length = length

        self._context = (offset, length, value)
        return

    def __str__(self):
        RakeMatch._has_been_read = True
        return "|".join(map(lambda x: str(x), self.aslist()))

    def aslist(self) -> list:
        RakeMatch._has_been_read = True
        outp = []

        if RakeMatch.fields['file']: outp.append(self.file)
        if RakeMatch.fields['line']: outp.append(self.line)
        if RakeMatch.fields['label']: outp.append(self.label)
        if RakeMatch.fields['severity']: outp.append(self.severity)
        if RakeMatch.fields['description']: outp.append(self.description)

        if RakeMatch.fields['value_offset']: outp.append(self.value_offset)
        if RakeMatch.fields['value_length']: outp.append(self.value_length)

        val = self.value if not RakeMatch._secure else None
        if RakeMatch.fields['value']: outp.append(val)

        if RakeMatch.fields['context_offset']: outp.append(self.context_offset)
        if RakeMatch.fields['context_length']: outp.append(self.context_length)

        ctx = self.context if not RakeMatch._disable_context else None
        if RakeMatch.fields['context']: outp.append(ctx)

        return outp

    def asdict(self):
        RakeMatch._has_been_read = True
        d = { "path":        self.file,
              "line":        int(self.line) if self.line is not None else None,
              "type":        self.label,
              "description": self.description,
              "severity":    self.severity }

        if not RakeMatch._disable_context:
            d['context'] = { "value": self.context,
                             "offset": self.context_offset,
                             "length": self.context_length }

        if not RakeMatch._disable_value:
            d['value'] =   { "value": self.value if not RakeMatch._secure else None,
                             "offset": self.value_offset,
                             "length": self.value_length }

        return d


class RakeSet(object):
    '''
    A wrapper (list) of RakePattern objects.  Each pattern in this list will
    be evaluated against each line of input text.
    '''
    def __init__(self, verbose:bool=False):
        self.content_rakes = list()
        self.meta_rakes = list()
        self.verbose = verbose

        # metrics for this rake set
        self.total_files = 0
        self.total_lines = 0
        self.total_hits = 0
        self.total_size = 0

        return

    def add(self, rake:Rake):
        if self.verbose:
            print("* Adding new Rake: " + str(rake), file=sys.stderr)

        if rake.part == 'filemeta':
            self.meta_rakes.append(rake)
            return

        if rake.part == 'content':
            self.content_rakes.append(rake)
            return

        raise RuntimeError("Unknown rake type")

    def match_context(self, context:dict):
        hits = list()
        for rake in self.meta_rakes:
            rm = rake.match(context)
            # The rake's match() is responsible for applying its own filter
            # chain and returning None on no-match; we just collect.
            if rm is None: continue
            hits.append(rm)

        return hits

    def match_content(self, context, text:str):
        matches = []
        for rake in self.content_rakes:
            if self.verbose: print(f"using rake: {rake} at {context}: {text}")
            mset = rake.match(context, text)
            for m in mset:
                if rake.filter(m) is False: continue
                matches.append(m)

        return matches

    # Default set of file extensions which are never read (binary/archive).
    DEFAULT_BLACKLIST = [".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                         ".tiff", ".zip", ".doc", ".docx", ".xls", ".xlsx",
                         ".pdf", ".tar", ".tgz", ".gz", ".tar.gz",
                         ".jar", ".war", ".ear", ".class", ".css"]

    # Number of bytes sampled from the head of each file for encoding
    # detection.  chardet is accurate on a small sample and we don't want to
    # read entire (potentially large) files just to guess encoding.
    ENCODING_SAMPLE_SIZE = 2048

    @staticmethod
    def _detect_encoding(fullpath:str) -> Optional[str]:
        '''
        Sample the first ENCODING_SAMPLE_SIZE bytes of a file and use chardet
        to guess its text encoding.  Returns the detected encoding name (eg,
        'utf-8', 'utf-16', 'ISO-8859-1') or None if the file cannot be read or
        no encoding could be determined (eg, an empty file).

        Runs on the worker thread (called from scan()), so the sampling read
        is parallelised along with the full scan.
        '''
        try:
            with open(fullpath, 'rb') as fd:
                sample = fd.read(RakeSet.ENCODING_SAMPLE_SIZE)
        except OSError:
            return None

        if not sample:
            return None

        result = chardet.detect(sample)
        return result.get('encoding')

    def scan(self, context:dict, blacklist=None):
        '''
        Scan a single file described by 'context' and return a
        (findings, stats) tuple.

        This method does NOT mutate any shared RakeSet state and does NOT
        write output, so it is safe to invoke concurrently from worker
        threads.  Each context is produced fresh by DirectoryWalker and is
        owned exclusively by the thread scanning it (we mutate only
        context['lineno']), so no locking is required.

        stats is a dict of per-file counters: files, lines, hits, bytes.
        '''
        if blacklist is None:
            blacklist = RakeSet.DEFAULT_BLACKLIST

        stats = {"files": 0, "lines": 0, "hits": 0, "bytes": 0}
        findings = list()

        if self.verbose:
            print(f"* New context: {str(context)}", file=sys.stderr)

        path = context.get("path", None)
        filename = context.get("filename", None)
        context['lineno'] = None

        if path is None or filename is None:
            if self.verbose:
                print("* Context is invalid?", file=sys.stderr)
            return findings, stats

        fullpath = context.get("fullpath", None)
        if fullpath is None:
            fullpath = os.path.join(path, filename)

        for ext in blacklist:
            if ext == filename[-len(ext):].lower():
                if self.verbose:
                    print(f"* File matches blacklisted extension: {ext}", file=sys.stderr)
                return findings, stats

        if self.verbose:
            print("* Applying context Rakes", file=sys.stderr)

        context_hits = self.match_context(context)
        if len(context_hits) > 0:
            findings.extend(context_hits)

        # Detect the file's text encoding (worker-side) and record it in the
        # context metadata.  Fall back to UTF-8 when detection is inconclusive
        # or names a codec Python doesn't recognize; a wrong-but-valid guess
        # still degrades gracefully via the UnicodeDecodeError handler below.
        encoding = self._detect_encoding(fullpath) or "utf-8"
        try:
            codecs.lookup(encoding)
        except LookupError:
            if self.verbose:
                print(f"* Unknown encoding {encoding!r} for {fullpath}; using utf-8",
                      file=sys.stderr)
            encoding = "utf-8"
        context["encoding"] = encoding

        try:
            fd = open(fullpath, encoding=encoding)
        except FileNotFoundError:
            if self.verbose:
                print(f"* Unable to open file: {fullpath}", file=sys.stderr)
            return findings, stats

        if self.verbose:
            print(f"* Applying content Rakes", file=sys.stderr)

        try:
            lineno = 1
            for line in fd:
                if self.verbose and lineno % 100 == 0:
                    print(f"* {lineno} lines processed ({fullpath})", file=sys.stderr)

                context['lineno'] = lineno
                hits = self.match_content(context, line)
                findings.extend(hits)

                lineno += 1
        except UnicodeDecodeError:
            # simply can't process this file due to encoding -- skip it.
            lineno = 0
        finally:
            fd.close()

        stats["files"] = 1
        stats["lines"] = lineno
        stats["hits"] = len(findings)

        try:
            stats["bytes"] = os.stat(fullpath).st_size
        except (FileNotFoundError, PermissionError):
            pass

        return findings, stats

    def match(self, context:dict, blacklist=None):
        '''
        Single-threaded convenience wrapper around scan().  Accumulates the
        per-file stats into the RakeSet's running totals and returns just the
        findings, preserving the original contract for non-threaded callers.
        '''
        findings, stats = self.scan(context, blacklist=blacklist)

        self.total_files += stats["files"]
        self.total_lines += stats["lines"]
        self.total_hits += stats["hits"]
        self.total_size += stats["bytes"]

        return findings


class RakeFilter(object):
    def __init__(self, ignorecase:bool=False):
        self.ignorecase = ignorecase
        return

    @staticmethod
    def load(config:dict) -> "RakeFilter":
        '''Build a single inline filter from a config dict.

        Only handles the directly-constructible filter types (regex, literal).
        Reference types ('named', 'set') require a FilterRegistry to resolve
        and are rejected here.
        '''
        t = config.get('type', None)
        if t is None: raise RuntimeError("Filter type not specified.")

        tl = t.lower()
        if tl == "regex":
            return RakeRegexFilter.load(config)

        if tl == "literal":
            return RakeLiteralFilter.load(config)

        if tl in ("named", "set"):
            raise RuntimeError(
                f"Filter type {t!r} requires a FilterRegistry to resolve "
                f"(reference {config.get('name')!r})")

        raise RuntimeError(f"Invalid filter type: {t}")

    def match(self, match:RakeMatch) -> bool:
        raise RuntimeError("Abstract method RakeFilter.match() called")


class FilterRegistry(object):
    '''Per-config registry of NamedFilters and FilterSets.

    A NamedFilter resolves to one RakeFilter; a FilterSet resolves to a list
    of RakeFilters that gets expanded inline wherever the set is referenced.
    Sharing a single RakeFilter instance across multiple rakes is safe because
    filter objects are read-only after construction.

    Each config load builds its own FilterRegistry, so multiple configurations
    can coexist (e.g. in tests) without cross-contamination.
    '''

    def __init__(self):
        self.named_filters:dict = {}    # name -> RakeFilter
        self.filter_sets:dict = {}      # name -> list[RakeFilter]
        return

    def register_named(self, name:str, filt:RakeFilter) -> None:
        if name in self.named_filters:
            raise RuntimeError(f"Duplicate NamedFilter name: {name!r}")
        if name in self.filter_sets:
            raise RuntimeError(
                f"Name {name!r} is already used by a FilterSet")
        self.named_filters[name] = filt

    def register_set(self, name:str, filters:list) -> None:
        if name in self.filter_sets:
            raise RuntimeError(f"Duplicate FilterSet name: {name!r}")
        if name in self.named_filters:
            raise RuntimeError(
                f"Name {name!r} is already used by a NamedFilter")
        self.filter_sets[name] = list(filters)

    def load(self, config:dict) -> RakeFilter:
        '''Resolve a single-filter config.

        Handles `type: named` lookups against the NamedFilter registry, and
        delegates everything else to RakeFilter.load.  A `type: set` here is
        an error -- use load_list for filter lists where sets can expand.
        '''
        t = config.get('type', '').lower() if isinstance(config, dict) else ''
        if t == 'named':
            name = config.get('name')
            if name is None:
                raise RuntimeError("NamedFilter reference missing 'name'")
            if name not in self.named_filters:
                raise RuntimeError(f"Unknown NamedFilter: {name!r}")
            return self.named_filters[name]
        if t == 'set':
            raise RuntimeError(
                f"FilterSet {config.get('name')!r} cannot be used where a "
                f"single filter is required; use it in a filter list instead")
        return RakeFilter.load(config)

    def load_list(self, configs:list) -> list:
        '''Flatten a list of filter-config entries into a list of filters.

        Each entry may be:
          - an inline filter (`type: regex` or `type: literal`)
          - a NamedFilter reference (`type: named`, `name: ...`)
          - a FilterSet reference (`type: set`, `name: ...`)

        FilterSet references are expanded inline; order is preserved.
        '''
        out = []
        for c in configs:
            t = c.get('type', '').lower() if isinstance(c, dict) else ''
            if t == 'set':
                name = c.get('name')
                if name is None:
                    raise RuntimeError("FilterSet reference missing 'name'")
                if name not in self.filter_sets:
                    raise RuntimeError(f"Unknown FilterSet: {name!r}")
                out.extend(self.filter_sets[name])
                continue
            out.append(self.load(c))
        return out


class RakeLiteralFilter(RakeFilter):
    def __init__(self,
                 key:Optional[str]=None,
                 val:Optional[str]=None,
                 ignorecase:bool=False):

        RakeFilter.__init__(self, ignorecase = ignorecase)

        if key is None and val is None:
            raise RuntimeError("One of key or value must be set for literal filter.")

        if self.ignorecase:
            key = key.lower() if key is not None else None
            val = val.lower() if val is not None else None

        self._key = key
        self._val = val
        return

    def __str__(self) -> str:
        return f"<RakeLiteralFilter(key={self._key}, val={self._val})>"

    def match(self, match:RakeMatch) -> bool:
        # Note that one of self._val or self._key MUST be set.
        if self._val is not None:
            v = str(match.value) if match.value is not None else None
            if v is None: return False

            if self.ignorecase:
                v = v.lower()
            
            if v != self._val: return False

        if self._key is not None:
            k = str(match.key) if match.key is not None else None
            if k is None: return False

            if self.ignorecase:
                k = k.lower()
            
            if k != self._key: return False

        return True

    @staticmethod
    def load(config:dict) -> RakeFilter:
        k = config.get('key', None)
        v = config.get('value', None)
        i = config.get('ignorecase', False)
        return RakeLiteralFilter(key=k, val=v, ignorecase=i)


class RakeRegexFilter(RakeFilter):

    def __init__(self,
                 key:Optional[str]=None,
                 val:Optional[str]=None,
                 ignorecase:bool=False):
        RakeFilter.__init__(self, ignorecase = ignorecase)

        if key is None and val is None:
            raise RuntimeError("One of key or value must be set for regex filter.")

        flags = 0   # default re flags
        if self.ignorecase:
            flags = re.IGNORECASE

        self._key = re.compile(key, flags=flags) if key is not None else None
        self._val = re.compile(val, flags=flags) if val is not None else None

        return

    def __str__(self) -> str:
        return f"<RakeRegexFilter(key={self._key}, val={self._val})>"

    def match(self, match:RakeMatch) -> bool:
        # Note that one of self._val or self._key MUST be set.
        # TODO: check ignorecase flag?
        if self._val is not None:
            mv = str(match.value)
            if not self._val.match(mv): return False
            
        if self._key is not None:
            mk = str(match.key)
            if not self._key.match(mk): return False
            
        return True

    @staticmethod
    def load(config:dict) -> RakeFilter:
        k = config.get('key', None)
        v = config.get('value', None)
        i = config.get('ignorecase', False)

        return RakeRegexFilter(key=k, val=v, ignorecase=i)