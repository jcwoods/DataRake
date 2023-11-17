import hashlib
import os
import sys

from collections import OrderedDict

class RakeMatch:
    pass

class Rake:
    pass

class DirectoryWalker:

    def __init__(self, path:str=".", blacklist=None, verbose:bool=False):
        '''
        path is the path to be traversed.

        blacklist is a list of DIRECTORIES to be excluded.  By default, source
        control directories (.svn, .git) will be used.
        '''

        if blacklist is None:
            blacklist = [ '.svn', '.git', '__pycache__' ]

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
            if rake.match(context):
                rm = RakeMatch(rake,
                               file=Rake.relPath(context['basepath'],
                               context['fullpath']),
                               line=None)
                if rake.filter(rm) is False: continue
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

    def match(self, context:dict, blacklist=None):
        if blacklist is None:
            blacklist = [".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                         ".tiff", ".zip", ".doc", ".docx", ".xls", ".xlsx",
                         ".pdf", ".tar", ".tgz", ".gz", ".tar.gz",
                         ".jar", ".war", "ear", ".class", ".css" ]

        if self.verbose:
            print(f"* New context: {str(context)}", file=sys.stderr)

        path = context.get("path", None)
        filename = context.get("filename", None)
        context['lineno'] = None

        findings = list()

        if path is None or filename is None:
            # log an error here
            if self.verbose:
                print("* Context is invalid?", file=sys.stderr)
            return findings

        fullpath = context.get("fullpath", None)
        if fullpath is None:
            fullpath = os.path.join(path, filename)

        for ext in blacklist:
            # log message here
            if ext == filename[-len(ext):].lower():
                if self.verbose:
                    print(f"* File matches blacklisted extension: {ext}", file=sys.stderr)
                return findings

        if self.verbose:
            print("* Applying context Rakes", file=sys.stderr)

        context_hits = self.match_context(context)
        if len(context_hits) > 0:
            findings.extend(context_hits)

        try:
            fd = open(fullpath, encoding="utf-8")
        except FileNotFoundError:
            if self.verbose:
                print(f"* Unable to open file: {fullpath}", file=sys.stderr)
            return findings

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

        fd.close()

        self.total_files += 1
        self.total_lines += lineno
        self.total_hits += len(findings)

        try:
            self.total_size += os.stat(fullpath).st_size
        except (FileNotFoundError, PermissionError):
            pass

        return findings


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
                          ('value_offset', True),
                          ('value_length', True),
                          ('value', True),
                          ('context_offset', True),
                          ('context_length', True),
                          ('context', True)))

    _secure = False
    _disable_context = False
    _disable_value = False
    _has_been_read = False

    def __init__(self, rake:Rake, file:str=None, line:int=0):
        self._label = rake.ptype
        self._description = rake.pdesc
        self._severity = rake.severity
        self._file = file
        self._line = line

        # these will be set by set_key(), set_value(), and set_context()
        self._key = None
        self._value = None
        self._context = None

        return

    def secureContext(self):
        '''
        Produce a hash which can be use to (reasonably) securely track a
        secret if it moves within a file.  The hash will consist of the file
        name, length of the context, and the literal value of the context.
        '''
        ctx = self._context[2]
        if ctx is None:
            return ""

        md5 = hashlib.md5()
        md5.update(self._file.encode('utf-8'))
        md5.update(bytes([0x00]))
        md5.update(ctx.encode('utf-8'))   # context value

        return md5.hexdigest()

    def __eq__(self, match):
        if self._value is None and match._value is not None: return False
        if self._value is not None and match._value is None: return False
        if self._value is not None and match._value is not None:
            if self._value[0] != match._value[0]: return False  # offset
            if self._value[1] != match._value[1]: return False  # length
            if self._value[2] != match._value[2]: return False  # value

        if self._context is None and match._context is not None: return False
        if self._context is not None and match._context is None: return False
        if self._context is not None and match._context is not None:
            if self._context[0] != match._context[0]: return False  # offset
            if self._context[1] != match._context[1]: return False  # length
            if self._context[2] != match._context[2]: return False  # value

        if self._label != match._label: return False
        if self._description != match._description: return False
        if self._severity != match._severity: return False
        if self._file != match._file: return False
        if self._line != match._line: return False

        return True

    def __getattr__(self, k):
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
            i = "\u001e".join(map(lambda x: str(x), self.aslist()))  # \u001e is information (field) separator
            return hashlib.md5(i.encode('utf-8')).hexdigest()

        raise KeyError(f"Invalid key for RakeMatch: {k}")

    @staticmethod
    def csv_header():
        RakeMatch._has_been_read = True
        fields = []
        for f in RakeMatch.fields.keys():
            if RakeMatch.fields[f]:
                fields.append(f)

        return fields

    @staticmethod
    def set_secure():
        if RakeMatch._has_been_read:
            raise RuntimeError("must not modify RakeMatch structure after read")

        RakeMatch._secure = True
        RakeMatch.fields['context'] = True
        RakeMatch.fields['value'] = False
        return

    @staticmethod
    def disable_context():
        if RakeMatch._has_been_read:
            raise RuntimeError("must not modify RakeMatch structure after read")

        RakeMatch._disable_context = True
        RakeMatch.fields['context_offset'] = False
        RakeMatch.fields['context_length'] = False
        RakeMatch.fields['context'] = False
        return

    @staticmethod
    def disable_value():
        if RakeMatch._has_been_read:
            raise RuntimeError("must not modify RakeMatch structure after read")

        RakeMatch._disable_value = True
        RakeMatch.fields['value_offset'] = False
        RakeMatch.fields['value_length'] = False
        RakeMatch.fields['value'] = False
        return

    def set_key(self, key:str=None, offset:int=None, length:int=None):
        '''
        key differs from value and context in that it will (generally) not be
        output.  It is optional, and used (almost) exclusively for match
        filtering.
        '''

        if length is None:
            length = len(key)

        self._key = (offset, length, key)
        return

    def set_value(self, value:str=None, offset:int=None, length:int=None):
        if length is None:
            length = len(value)

        self._value = (offset, length, value)
        return

    def set_context(self, value:str=None, offset:int=None, length:int=None):
        if length is None:
            self._length = len(value)

        self._context = (offset, length, value)
        return

    def __str__(self):
        RakeMatch._has_been_read = True
        return "|".join(map(lambda x: str(x), self.aslist()))

    def aslist(self):
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