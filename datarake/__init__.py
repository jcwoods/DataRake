import argparse
import base64
import csv
import hashlib
import json
import math
import os
import re
import sys

from collections import Counter, OrderedDict

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

# Rakes are added to RakeSets.  RakeSets are applied to files.
# There are two types of Rakes:  File context and Content.
#
# A file context Rake will be executed ONCE for each file.  It will evaluate
# properties of the file, such as path, name, or extension.
#
# A content Rake will be executed once for each line in a file.  If a file
# is found to contain non-text (specifically, non-UTF8) data, processing will
# be aborted immediately.
#
# While the two types of Rakes may be run independently, the RakeSet
# orchestrates the running of a large number of rakes (of both types) on a
# single file.
#
# How filtering works:  Any Rake may add a 'filter' method accepting a
# RakeMatch argument as a single parameter.  This method will be called
# (in RakeSet.match()) after the Rake has been executed but before the
# result is added to the output result set.  A default filter() method has
# been added to the top level Rake class which will pass all matches if no
# specific filter is added to a rake.
#
# The filter() method will have access to all fields in the RakeMatch to
# use to determine whether the result should be filtered or not.  If the match
# should be filtered, the method should return False (this is consistent with
# the expectation of the python built-in filter() method).  Otherwise, the
# method should return True (the match is kept).
#
# Note that in the RakePattern class that the match groups from the re.findall
# call are preserved.  THis provides pre-parsed fields beyond what is
# available in the RakeMatch value and context fields without having to re-
# parse the text.

# Some neat ideas which might get implemented one day:
# TODO - look inside archive files (.zip, .tgz)?
# TODO - search for passwords in XML

# Design changes
# TODO - all rakes have severity, type, and desc, move to the Rake class.

class DirectoryWalker:

    def __init__(self, path=".", blacklist = None, verbose=False):
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


class Rake(object):
    '''
    A Rake is an abstract "issue finder".  Its subclasses do all of the real
    work.  When applied or executed, it creates RakeMatch objects.  Rake
    objects are grouped in RakeSet collections when many Rakes will be
    applied repeatedly.
    '''

    def __init__(self, ptype, pdesc, severity, part = 'content'):
        self.name = self.__class__.__name__
        self.ptype = ptype        # rake type (password, token, private key, etc)
        self.pdesc = pdesc        # long(er) description of rake
        self.severity = severity  # finding severity
        self.part = part          # where is rake applied? (content, filemeta, etc.)
        return

    def __str__(self):
        return f"<Rake({self.name}, {self.ptype}, {self.part})>"

    @staticmethod
    def relPath(basepath, fullpath):

        bplen = len(basepath)
        relpath = fullpath[bplen:]

        while relpath[0] == '/':
            relpath = relpath[1:]

        #print(f"relpath:  {relpath}")
        return  relpath

    def filter(self, m=None):
        '''
        A generic filter method.  If filter() returns false (eg, a match should
        be filtered), the result will not be added to the result set.

        Note that this is only a fail-safe, and that filters must be
        implemented within the context of a specific Rake-type.  The 'm'
        (match) parameter may be of different types and must be interpreted
        differently.
        '''
        return True


class RakeFileMeta(Rake):
    '''
    Creates RakeMatch based on file metadata (name, path, extension) rather
    than content.

    If self.all_required is set to true, all patterns which have been
    defined MUST return true.  Otherwise, we will return a positive
    result when the first match is made.
    '''

    def __init__(self, ptype, pdesc, severity,
                       path=None,    # pattern applied to path (dirname)
                       file=None,    # pattern applied to file name (basename)
                       ext=None,     # pattern applied to file extension
                       all=True,     # pattern applied to path
                       ignorecase=True,  # set re.IGNORECASE on regex matching
                       **kwargs):

        Rake.__init__(self, ptype, pdesc, severity, part='filemeta', **kwargs)

        f = re.IGNORECASE if ignorecase else 0
        self.path_pattern = None if path is None else re.compile(path, flags=f)
        self.file_pattern = None if file is None else re.compile(file, flags=f)
        self.ext_pattern = None if ext is None else re.compile(ext, flags=f)
        self.all_required = all
        return

    def match(self, context):
        path = context.get('path', None)
        fnam = context.get('filename', None)
        ext = context.get('filetype', None)
        full = context.get('fullpath', None)

        # create the match up front, just in case!
        m = RakeMatch(self, file=full, line=None)

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
        RakeFileMeta.__init__(self, 'ssh identity file',
                                    'file (likely) containing an ssh private key',
                                    'HIGH',
                                    file=r"^id_(rsa1?|dsa|ecdsa|ed25519)$",
                                    ignorecase=False)
        return


class RakeNetrc(RakeFileMeta):
    '''
    Network credential storage.
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'netrc file',
                                    'file containing network credentials',
                                    'HIGH',
                                    file=r"^.?netrc$",
                                    ext=r"netrc",
                                    all=False)
        return

class RakePKIKeyFiles(RakeFileMeta):
    '''
    Files often related with PKI/X509 keys.
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'x509 key file',
                                    'files often related to PKI/X509 (server certificates and/or keys)',
                                    'MEDIUM',
                                    ext=r"^(pem|pfx|p12|p7b|key)$")
        return

class RakeKeystoreFiles(RakeFileMeta):
    '''
    Files often related with Java keystores.
    TODO:  test default/simple passwords (changeit, changeme, password)
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'java keystore',
                                    'patterns in file name are associated with Java keystores',
                                    'MEDIUM',
                                    file=r"^keystore$",
                                    ext=r"^(jks|keystore)$",
                                    all=False)
        return

class RakeHtpasswdFiles(RakeFileMeta):
    '''
    Apache htpasswd files.
    '''
    def __init__(self):
        RakeFileMeta.__init__(self, 'apache htpasswd',
                                    'may contain credentials used to access Apache resources',
                                    'LOW',
                                    file=r"^\.?htpasswd$")
        return

class FiletypeContextRake(Rake):
    '''
    Manages a set of Rakes, applying each based on file type (extension).
    '''

    def __init__(self, ptype, pdesc, severity, **kwargs):
        Rake.__init__(self, ptype, pdesc, severity, part='content', **kwargs)
        self.rakes = dict()
        return

    def addRakePattern(self, filetype, rake):
        self.rakes[filetype] = rake
        return

    def match(self, context, text):
        filetype = context.get("filetype", None)

        rake = None
        if filetype is not None:
            # find a rake matching file type
            filetype = filetype.lower()
            rake = self.rakes.get(filetype, None)

        if rake is None:
            # is there a default rake?
            rake = self.rakes.get(None, None)

            if rake is None:
                # no default, empty match set
                return []

        mset = rake.match(context, text)
        return mset


class RakeToken(FiletypeContextRake):
    '''
    Detect tokens embedded in code or configurations.  This is context
    sensitive (based on file type).
    '''

    def __init__(self, minlength:int=6, **kwargs):
        FiletypeContextRake.__init__(self, 'token',
                                           'possible token, authentication key, or similar',
                                           'HIGH',
                                           **kwargs)
        self.minlength = minlength

        # add the default pattern (no other match)
        r = r"(([\"']?)(auth)?tok(en)?(\2)[ \t]*[=:][ \t]*(['\"]?)([\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",})(\6))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=5)
        self.addRakePattern(None, rake)

        # c, c++, java
        r = r'((auth)?tok(en)?[ \t]*=[ \t]*"([\x21\x23-\x26\x28-\x7e]{' + str(minlength) + r',})")'
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=4)
        self.addRakePattern("c", rake)
        self.addRakePattern("h", rake)
        self.addRakePattern("cc", rake)
        self.addRakePattern("cpp", rake)
        self.addRakePattern("hpp", rake)
        self.addRakePattern("java", rake)

        # js, py
        r = r"((auth)?tok(en)?[ \t]*=[ \t]*(['\"])([\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",})(\4))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=4)
        self.addRakePattern("js", rake)
        self.addRakePattern("py", rake)

        # yaml, yml
        r = r"((auth)?tok(en)?[ \t]*:[ \t]*(['\"]?)([\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",})(\4))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=4)
        self.addRakePattern("yaml", rake)
        self.addRakePattern("yml", rake)

        # shell, ini
        r = r"((auth)?tok(en)?[ \t]*=[ \t]*(['\"]?)([^\$][\x21\x23-\x26\x28-\x7e]{" + str(minlength-1) + r",})(\4))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=4)
        self.addRakePattern("sh", rake)
        self.addRakePattern("ini", rake)

        return


class RakePassword(FiletypeContextRake):
    '''
    Detect passwords embedded in code or configurations.  This is context
    sensitive (based on file type).
    TODO: support php "key => value" syntax
    '''

    def __init__(self, minlength=6, **kwargs):
        FiletypeContextRake.__init__(self, 'password',
                                           'possible plaintext password',
                                           'HIGH',
                                           **kwargs)
        self.minlength = minlength

        # add the default pattern (no other match)
        r = r"(([\"']?)pass(w(ord)?)?(\2)[ \t]*[=:][ \t]*(['\"]?)([\x21\x23-\x26\x28-\x7e]){" + str(minlength) + r",}(\6))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=6)
        self.addRakePattern(None, rake)

        # c, c++, java
        r = r'(pass(w(ord)?)?[ \t]*=[ \t]*"([\x21\x23-\x26\x28-\x7e]{' + str(minlength) + r',})")'
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=3)
        self.addRakePattern("c", rake)
        self.addRakePattern("h", rake)
        self.addRakePattern("cc", rake)
        self.addRakePattern("cpp", rake)
        self.addRakePattern("hpp", rake)
        self.addRakePattern("java", rake)

        # js, py
        r = r"(pass(w(ord)?)?[ \t]*=[ \t]*(['\"])([\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",})(\4))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=4)
        self.addRakePattern("js", rake)
        self.addRakePattern("py", rake)

        # yaml, yml
        r = r"(pass(w(ord)?)?[ \t]*:[ \t]*(['\"]?)([\x21\x23-\x26\x28-\x7e]{" + str(minlength) + r",})(\4))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=4)
        self.addRakePattern("yaml", rake)
        self.addRakePattern("yml", rake)

        # shell, ini
        r = r"(pass(w(ord)?)?[ \t]*=[ \t]*(['\"]?)([^\$][\x21\x23-\x26\x28-\x7e]{" + str(minlength-1) + r",})(\4))"
        rake = RakePattern(r, self.ptype, self.pdesc, self.severity, ctx_group=0, val_group=4)
        self.addRakePattern("sh", rake)
        self.addRakePattern("ini", rake)

        return

    def filter(self, m=None):
        val = m.value
        if val is None: return True
        if val.lower() in ['password']: return False
        return True


class RakePattern(Rake):
    '''
    This is a basic pattern.  It will be compiled into a regex.
    '''

    def __init__(self, pattern, ptype, pdesc, severity, ctx_group=None, val_group=None, ignorecase=True):
        '''
        pattern is the pattern to be matched in the input text.
        ptype is the type of the pattern, supplied by the subclass.
        '''
        Rake.__init__(self, ptype, pdesc, severity, part='content')

        flags = 0
        if ignorecase:
            flags = re.IGNORECASE

        self.pattern = re.compile(pattern, flags=flags)
        self.ctx_group = ctx_group  # position (group) of context match in output tuple
        self.val_group = val_group  # position (group) of value match in output tuple

        return

    def match(self, context, text):
        mset = []

        relpath = None
        offset = 0
        for m in self.pattern.findall(text):
            if isinstance(m, tuple):
                val = m[self.val_group] if self.val_group is not None else None
                ctx = m[self.ctx_group] if self.ctx_group is not None else None
            else:
                val = m if self.val_group is not None else None
                ctx = m if self.ctx_group is not None else None

            if relpath is None:
                relpath = self.relPath(context['basepath'], context['fullpath'])

            rm = RakeMatch(self,
                           file=relpath,
                           line=context['lineno'])

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
            mset.append(rm)

        return mset


class RakeSet(object):
    '''
    A wrapper (list) of RakePattern objects.  Each pattern in this list will
    be evaluated against each line of input text.
    '''
    def __init__(self, verbose=False):
        self.content_rakes = list()
        self.meta_rakes = list()
        self.verbose = verbose
        return

    def add(self, rake):
        if self.verbose:
            print("* Adding new Rake: " + str(rake), file=sys.stderr)

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
            mset = rake.match(context, text)
            for m in mset:
                if rake.filter(m) is False: continue
                matches.append(m)

        return matches

    def match(self, context, blacklist=None):
        if blacklist is None:
            blacklist = [".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                         ".tiff", ".zip", ".doc", ".docx", ".xls", ".xlsx",
                         ".pdf", ".tgz", ".gz", ".tar.gz",
                         ".jar", ".war", "ear", ".class" ]
        
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
            pass

        fd.close()
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

        # these will be set by set_value() and set_context()
        self._value = None
        self._context = None

        return

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
                if RakeMatch._secure or self._context is None: return None
                return self._context[2]

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
        RakeMatch.fields['context'] = False
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

        ctx = self.context if not RakeMatch._secure else None
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
            d['context'] = { "value": self.context if not RakeMatch._secure else None,
                             "offset": self.context_offset,
                             "length": self.context_length }

        if not RakeMatch._disable_value:
            d['value'] =   { "value": self.value if not RakeMatch._secure else None,
                             "offset": self.value_offset,
                             "length": self.value_length }

        return d


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

    # a list of TLDs for hostname checks (these account for more than 99% of
    # hosts on the internet)
    TLDs = [ 'au', 'br', 'cn', 'com', 'de', 'edu', 'gov', 'in', 'info', 'ir',
             'mil', 'net', 'nl', 'org', 'ru', 'tk', 'top', 'uk', 'xyz' ]

    def __init__(self, domain=None, **kwargs):
        if domain is not None:
            d = re.escape(domain)
            r = r'\b(([a-z1-9\-]+\.)+' + d + r')\b'
        else:
            # going to make an arbitrary call here... domain must be 2 or
            # more "parts".  A name will need to be "host.d1.d2", We'll miss
            # things like "localhost.localdomain" but that should be
            # acceptable since we're not picking up 'a.b'-type symbols.  If
            # you don't like this, change the "{2,}" below to a simple "+".
            r = r'\b([a-z1-9\-]+(\.[a-z1-9\-]+){2,})\b'

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


class RakeURL(RakePattern):
    '''
    Detect URLs.  If credentials is set to True (default), only URLs with
    embedded credentials will be reported.
    '''

    def __init__(self, **kwargs):
        '''
        a very crude pattern to match URLs, roughly of the pattern:
            xxx://user:pass@xxx.xxx:ppp/zzz+
        '''
        r = r'\b([a-z]{2,8}://(([a-z0-9%+/=\-]+):([a-z0-9%+/=\-]+))@([A-Z0-9_-]+(\.[A-Z0-9_-]+)+)(:\d{1,5})?(/(\S*)?)?)\b'
        RakePattern.__init__(self,
                             r,
                            'auth url',
                            'URL containing credentials (basic auth)',
                            'HIGH',
                             ctx_group=0, val_group=1, **kwargs)
        return

    def filter(self, m=None):
        '''
        If this method returns False, the match (m) will be suppressed.  See
        the filter() method on the Rake class for more information.
        '''

        if m is None: return True
        groups = m.match_groups

        usern = groups[2]
        passw = groups[3]
        host = groups[4]

        if usern.lower() in ['user', 'username'] and passw.lower() in ['pass', 'password']:
            return False

        dparts = host.lower().split('.')
        if len(dparts) >= 2 and \
           dparts[-2] in ['example', 'host', 'hostname', 'domain', 'domainname'] and \
           dparts[-1] in ['org', 'com', 'net']: return False

        return True


class RakeEmail(RakePattern):
    '''
    Detect email addresses.  If domain is not None, the domain associated with
    the email account must match the specified domain.
    '''

    def __init__(self, domain = None, **kwargs):
        if domain is not None:
            d = re.escape(domain)
            r = r'([a-zA-Z1-9_.\-]+@' + d + r')'
        else:
            r = r'([a-zA-Z0-9_.\-]+@[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+)'

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
        kp = r'^(-----BEGIN ([A-Z0-9]{2,} )?PRIVATE KEY-----)$'
        RakePattern.__init__(self, kp,
                                 'private key',
                                 'header indicating presence of a private key in a PEM format',
                                 'HIGH',
                                 ctx_group=0, val_group=None, ignorecase=False, **kwargs)

        return


class RakeBearerAuth(RakePattern):
    '''
    Find likely Bearer auth tokens (as used in HTTP headers).  Eg,

        Authorization: Bearer 986272DF-F26E-4A47-A1E4-B0FC0024A3EE
    '''

    def __init__(self, **kwargs):
        kp = r'(Bearer (\S{8,}))'
        RakePattern.__init__(self, kp,
                                  'auth bearer',
                                  'possible value used with an Authorization: header',
                                  'HIGH',
                                   ctx_group=0, val_group=1, ignorecase=False, **kwargs)
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
        kp = r'(Basic ([A-Za-z0-9+/]{'+ str(minlen) + r',}={0,8}))$'
        RakePattern.__init__(self, kp,
                                  'auth basic',
                                  'possible value used with an Authorization: header',
                                  'HIGH',
                                  ctx_group=0, val_group=1, ignorecase=False, **kwargs)
        self.encoding = encoding
        return

    def match(self, context, text:str):
        mset = []
        for m in self.pattern.findall(text):
            # we may or may not have something juicy... let's attempt to
            # decode it and see if it checks out!
            try:
                encoded = m[6:]  # skip leading "Basic " label
                val = base64.b64decode(encoded, validate=True).decode(self.encoding).strip()
            except Exception:
                # not base64 means this probably isn't a token.
                continue

            # does it smell like basic auth?  (user:pass)
            if not val.isprintable() or val.find(":") < 1:
                continue

            m = RakeMatch(self,
                          file=self.relPath(context['basepath'], context['fullpath']),
                          line=context['lineno'])

            m.set_context(value=" ".join(("Basic", val)), offset=0, length=len(encoded) + 6)
            m.set_value(value=val, offset=6, length=len(encoded))
            mset.append(m)

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
        kp = r'\b(([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/]{24,}={0,2})\.([A-Za-z0-9+/]{24,}={0,2}))\b'
        RakePattern.__init__(self, kp,
                                  'auth jwt',
                                  'possible JavaScript web token',
                                  'MEDIUM',
                                  ignorecase=False, **kwargs)

        self.encoding = encoding
        return

    def match(self, context, text:str):
        mset = []
        relfile = None
        for m in self.pattern.findall(text):
            # we may or may not have something juicy... let's attempt to
            # decode it and see if it checks out!
            if self.encoding is not None:
                try:
                    t0 = base64.b64decode(m[1]).decode('utf-8')
                    t1 = base64.b64decode(m[2]).decode('utf-8')

                    # all we care is that the JSON decode works!  If it
                    # fails, this isn't JWT.
                    json.loads(t0)
                    json.loads(t1)
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

        return mset


class RakeAWSHMACAuth(RakePattern):
    '''
    Find AWS4-HMAC-SHA256 authorization headers, eg:

        Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024

    See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
    '''
    def __init__(self, **kwargs):
        kp = r'(AWS-HMAC-SHA256 (.+))$'
        RakePattern.__init__(self, kp,
                                  'auth aws-hmac-sha256',
                                  'possible AWS HMAC-SHA256 authorization key',
                                  'HIGH',
                                  ctx_group=0, val_group=1, ignorecase=False, **kwargs)
        return


class RakeSSHPass(RakePattern):
    '''
    Find uses of sshpass command (non-interactive ssh authentication).
    '''
    def __init__(self, **kwargs):
        kp = r'\b(sshpass .*-p\s?([\'"]?)(\S+)(\2))'
        RakePattern.__init__(self, kp,
                                  'sshpass use',
                                  'Use of sshpass using hard-coded password',
                                  'HIGH',
                                  ctx_group=0, val_group=2, ignorecase=False, **kwargs)
        return

