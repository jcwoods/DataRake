"""Unit tests for the Rake class hierarchy.

Run from the project root with:
    python -m unittest discover -s tests -t .
"""

import base64
import json
import os
import unittest

from datarake.common import Rake, RakeMatch, RakeSet
from datarake.common import RakeFilter, RakeLiteralFilter, RakeRegexFilter
from datarake.common import FilterRegistry
from datarake.rakes import (
    RakeFileMeta,
    RakePattern,
    RakeContextPattern,
    RakeHostname,
    RakeEmail,
    RakeBasicAuth,
    RakeJWTAuth,
    SentinelRake,
)


def make_context(filename="x.txt", basepath="/scan", path=None, filetype=None, lineno=1):
    """Build the context dict expected by Rake.match() variants."""
    if path is None:
        path = basepath
    if filetype is None and "." in filename:
        filetype = filename.rsplit(".", 1)[-1]
    return {
        "basepath": basepath,
        "path": path,
        "filename": filename,
        "fullpath": os.path.join(path, filename),
        "filetype": filetype,
        "lineno": lineno,
    }


# ---------------------------------------------------------------------------
# Rake (base class)
# ---------------------------------------------------------------------------

class TestRakeBase(unittest.TestCase):

    def test_match_is_abstract(self):
        r = Rake("test", "desc", "LOW")
        with self.assertRaises(NotImplementedError):
            r.match({})

    def test_filter_default_returns_true(self):
        r = Rake("test", "desc", "LOW")
        rm = RakeMatch(r, file="f", line=1)
        self.assertIs(r.filter(rm), True)

    def test_invalid_part_raises(self):
        with self.assertRaises(RuntimeError):
            Rake("t", "d", "LOW", part="bogus")

    def test_relpath_strips_basepath(self):
        self.assertEqual(Rake.relPath("/foo", "/foo/bar/baz.txt"), "bar/baz.txt")

    def test_str_includes_class_and_type(self):
        r = Rake("token", "d", "LOW")
        s = str(r)
        self.assertIn("Rake", s)
        self.assertIn("token", s)


# ---------------------------------------------------------------------------
# RakeFileMeta
# ---------------------------------------------------------------------------

class TestRakeFileMeta(unittest.TestCase):

    def test_match_by_file_pattern(self):
        r = RakeFileMeta("pki", "desc", "MEDIUM", file=r"^id_rsa$", all=False)
        self.assertIsNotNone(r.match(make_context(filename="id_rsa")))

    def test_no_match_when_file_pattern_misses(self):
        r = RakeFileMeta("pki", "desc", "MEDIUM", file=r"^id_rsa$", all=False)
        self.assertIsNone(r.match(make_context(filename="other.txt")))

    def test_match_by_extension(self):
        r = RakeFileMeta("pki", "desc", "MEDIUM", ext=r"^pem$", all=False)
        self.assertIsNotNone(r.match(make_context(filename="cert.pem")))

    def test_extension_pattern_skipped_when_file_has_no_extension(self):
        r = RakeFileMeta("pki", "desc", "MEDIUM", ext=r"^pem$", all=False)
        ctx = make_context(filename="Makefile", filetype=None)
        self.assertIsNone(r.match(ctx))

    def test_all_required_true_requires_all_to_match(self):
        r = RakeFileMeta("test", "desc", "LOW",
                         path=r"^/scan", file=r"^foo$", all=True)
        good = make_context(filename="foo", path="/scan")
        bad_file = make_context(filename="bar", path="/scan")
        bad_path = make_context(filename="foo", path="/other", basepath="/other")
        self.assertIsNotNone(r.match(good))
        self.assertIsNone(r.match(bad_file))
        self.assertIsNone(r.match(bad_path))

    def test_all_required_false_any_can_match(self):
        r = RakeFileMeta("test", "desc", "LOW",
                         file=r"^foo$", ext=r"^bar$", all=False)
        self.assertIsNotNone(r.match(make_context(filename="foo")))
        self.assertIsNotNone(r.match(make_context(filename="x.bar")))
        self.assertIsNone(r.match(make_context(filename="baz.txt")))

    def test_no_patterns_defined_returns_none(self):
        r = RakeFileMeta("test", "desc", "LOW")
        self.assertIsNone(r.match(make_context(filename="foo")))

    def test_returned_file_path_is_relative(self):
        r = RakeFileMeta("test", "desc", "LOW", file=r"^foo$", all=False)
        ctx = make_context(filename="foo", basepath="/scan", path="/scan/sub")
        rm = r.match(ctx)
        self.assertIsNotNone(rm)
        self.assertEqual(rm.file, "sub/foo")

    def test_ignorecase(self):
        r = RakeFileMeta("test", "desc", "LOW",
                         file=r"^FOO$", ignorecase=True, all=False)
        self.assertIsNotNone(r.match(make_context(filename="foo")))

    def test_part_is_filemeta(self):
        r = RakeFileMeta("test", "desc", "LOW", file=r"^x$", all=False)
        self.assertEqual(r.part, "filemeta")

    def test_load_missing_name_raises(self):
        with self.assertRaises(RuntimeError):
            RakeFileMeta.load({"description": "d", "severity": "LOW", "file": "x"})

    def test_load_no_patterns_raises(self):
        with self.assertRaises(RuntimeError):
            RakeFileMeta.load({"name": "n", "description": "d", "severity": "LOW"})

    def test_load_builds_rake(self):
        r = RakeFileMeta.load({
            "name": "n", "description": "d", "severity": "HIGH",
            "file": r"^foo$", "all": False, "ignorecase": True,
        })
        self.assertEqual(r.ptype, "n")
        self.assertEqual(r.severity, "HIGH")
        self.assertIsNotNone(r.match(make_context(filename="FOO")))


# ---------------------------------------------------------------------------
# RakePattern
# ---------------------------------------------------------------------------

class TestRakePattern(unittest.TestCase):

    def test_basic_match_extracts_value(self):
        r = RakePattern(r"(token=(\w+))", "tok", "d", "LOW",
                        ctx_group=0, val_group=1)
        hits = r.match(make_context(), "foo token=abc123 bar")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "abc123")

    def test_no_match_returns_empty_list(self):
        r = RakePattern(r"(zzz)", "tok", "d", "LOW", ctx_group=0)
        self.assertEqual(r.match(make_context(), "no match here"), [])

    def test_multiple_matches_on_one_line(self):
        r = RakePattern(r"(token=(\w+))", "tok", "d", "LOW",
                        ctx_group=0, val_group=1)
        hits = r.match(make_context(), "token=aaa token=bbb token=ccc")
        self.assertEqual([h.value for h in hits], ["aaa", "bbb", "ccc"])

    def test_value_offset_uses_regex_position_not_first_occurrence(self):
        # Regression for review issue #6: previously text.find would
        # locate the first occurrence of the value, not the regex match.
        r = RakePattern(r"(foo=(token))", "x", "d", "LOW",
                        ctx_group=0, val_group=1)
        text = "token foo=token"
        hits = r.match(make_context(), text)
        self.assertEqual(len(hits), 1)
        # The captured "token" is at position 10, not 0
        self.assertEqual(hits[0].value_offset, 10)

    def test_value_length(self):
        r = RakePattern(r"(token=(\w+))", "tok", "d", "LOW",
                        ctx_group=0, val_group=1)
        hits = r.match(make_context(), "token=abc123")
        self.assertEqual(hits[0].value_length, 6)

    def test_ignorecase(self):
        r = RakePattern(r"(TOKEN=(\w+))", "tok", "d", "LOW",
                        ctx_group=0, val_group=1, ignorecase=True)
        hits = r.match(make_context(), "token=xyz")
        self.assertEqual(len(hits), 1)

    def test_filter_rejects_match(self):
        r = RakePattern(r"(token=(\w+))", "tok", "d", "LOW",
                        ctx_group=0, val_group=1)
        r.addFilter(RakeLiteralFilter(val="skipme"))
        hits = r.match(make_context(), "token=skipme token=keep")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "keep")

    def test_regex_filter(self):
        r = RakePattern(r"(token=(\S+))", "tok", "d", "LOW",
                        ctx_group=0, val_group=1)
        # Reject placeholder-looking ${...} values
        r.addFilter(RakeRegexFilter(val=r"\$\{[A-Z_]+\}"))
        hits = r.match(make_context(), "token=${TOKEN} token=realsecret")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "realsecret")

    def test_match_groups_preserves_empty_for_optional(self):
        # The finditer refactor uses groups(default='') to keep findall semantics.
        r = RakePattern(r"(foo(bar)?(baz))", "x", "d", "LOW", ctx_group=0)
        hits = r.match(make_context(), "foobaz")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].match_groups, ("foobaz", "", "baz"))

    def test_missing_ctx_group_raises(self):
        with self.assertRaises(RuntimeError):
            RakePattern(r"(foo)", "x", "d", "LOW")

    def test_invalid_regex_raises(self):
        # The init wraps a re.error and exits — but we shouldn't sys.exit
        # in tests. Use a pattern that's syntactically valid but unusable.
        # (Documenting: this is review issue #8 — currently calls sys.exit.)
        with self.assertRaises(SystemExit):
            RakePattern(r"(unclosed", "x", "d", "LOW", ctx_group=0)

    def test_load_from_config(self):
        r = RakePattern.load({
            "name": "n", "pattern": r"(foo)", "description": "d",
            "severity": "MEDIUM", "contextgroup": 0,
        })
        self.assertEqual(len(r.match(make_context(), "foo bar")), 1)

    def test_load_missing_pattern_raises(self):
        with self.assertRaises(RuntimeError):
            RakePattern.load({"name": "n", "contextgroup": 0})

    def test_load_with_filters(self):
        r = RakePattern.load({
            "name": "n", "pattern": r"(token=(\w+))",
            "description": "d", "severity": "LOW",
            "contextgroup": 0, "valgroup": 1,
            "filters": [
                {"type": "literal", "value": "ignoreme"},
            ],
        })
        hits = r.match(make_context(), "token=ignoreme token=keep")
        self.assertEqual([h.value for h in hits], ["keep"])


# ---------------------------------------------------------------------------
# SentinelRake
# ---------------------------------------------------------------------------

class TestSentinelRake(unittest.TestCase):

    # A pattern with capture groups so contextgroup/valgroup have something to
    # reference (group 1 = whole "secret=<val>", group 2 = the value).
    PATTERN = r"(secret=(\w{6,}))"
    SENTINEL = r"\bSENTINEL\b"

    def _rake(self, context_lines=3, ctx_group=0, val_group=1, **kw):
        return SentinelRake(self.SENTINEL, self.PATTERN, "aws", "desc", "HIGH",
                            context_lines=context_lines,
                            ctx_group=ctx_group, val_group=val_group, **kw)

    def _feed(self, rake, lines):
        """Feed lines through the rake in order, returning (value, line) hits."""
        ctx = make_context()
        hits = []
        for i, line in enumerate(lines, 1):
            ctx["lineno"] = i
            hits.extend(rake.match(ctx, line))
        return [(h.value, h.line) for h in hits]

    def test_part_is_content(self):
        self.assertEqual(self._rake().part, "content")

    def test_no_match_without_sentinel(self):
        r = self._rake()
        self.assertEqual(self._feed(r, ["secret=abcdef", "nothing", "here"]), [])

    def test_sentinel_before_pattern(self):
        r = self._rake(context_lines=3)
        hits = self._feed(r, ["SENTINEL", "x", "secret=abcdef"])
        self.assertEqual(hits, [("abcdef", 3)])

    def test_sentinel_after_pattern(self):
        r = self._rake(context_lines=3)
        hits = self._feed(r, ["secret=abcdef", "x", "SENTINEL"])
        # Reported against the line the pattern was found on, not the sentinel.
        self.assertEqual(hits, [("abcdef", 1)])

    def test_sentinel_same_line(self):
        r = self._rake()
        self.assertEqual(self._feed(r, ["SENTINEL secret=abcdef"]), [("abcdef", 1)])

    def test_sentinel_just_within_window(self):
        # distance == context_lines is still within range
        r = self._rake(context_lines=3)
        hits = self._feed(r, ["SENTINEL", "x", "x", "secret=abcdef"])
        self.assertEqual(hits, [("abcdef", 4)])

    def test_sentinel_just_outside_window(self):
        # distance == context_lines + 1 is out of range
        r = self._rake(context_lines=3)
        self.assertEqual(self._feed(r, ["SENTINEL", "x", "x", "x", "secret=abcdef"]), [])

    def test_reports_pattern_value_not_sentinel(self):
        r = self._rake()
        hits = self._feed(r, ["SENTINEL", "secret=topsecret"])
        self.assertEqual(hits, [("topsecret", 2)])

    def test_no_duplicate_when_sentinel_on_both_sides(self):
        r = self._rake(context_lines=5)
        hits = self._feed(r, ["SENTINEL", "secret=abcdef", "SENTINEL"])
        self.assertEqual(hits, [("abcdef", 2)])

    def test_multiple_patterns_each_confirmed(self):
        r = self._rake(context_lines=5)
        hits = self._feed(r, ["secret=aaaaaa", "secret=bbbbbb", "SENTINEL"])
        self.assertEqual(sorted(hits), [("aaaaaa", 1), ("bbbbbb", 2)])

    def test_state_is_per_context_not_per_rake(self):
        # Two files scanned with the same rake must not leak window state:
        # a sentinel in file A cannot confirm a pattern in file B.
        r = self._rake(context_lines=10)
        ctx_a = make_context(filename="a.txt")
        ctx_a["lineno"] = 1
        self.assertEqual(r.match(ctx_a, "SENTINEL"), [])

        ctx_b = make_context(filename="b.txt")
        ctx_b["lineno"] = 1
        # Fresh context => fresh window => no sentinel seen => no hit.
        self.assertEqual(r.match(ctx_b, "secret=abcdef"), [])

    def test_filter_rejects_match(self):
        r = self._rake()
        r.addFilter(RakeLiteralFilter(val="abcdef"))
        hits = self._feed(r, ["SENTINEL", "secret=abcdef", "secret=keepme"])
        self.assertEqual(hits, [("keepme", 3)])

    def test_value_and_context_groups(self):
        r = self._rake(ctx_group=0, val_group=1)
        ctx = make_context(lineno=1)
        hits = r.match(ctx, "SENTINEL secret=abcdef")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "abcdef")
        self.assertEqual(hits[0].context, "secret=abcdef")

    def test_negative_context_lines_raises(self):
        with self.assertRaises(RuntimeError):
            self._rake(context_lines=-1)

    def test_missing_groups_raises(self):
        with self.assertRaises(RuntimeError):
            SentinelRake(self.SENTINEL, self.PATTERN, "aws", "d", "HIGH",
                         context_lines=3, ctx_group=None, val_group=1)
        with self.assertRaises(RuntimeError):
            SentinelRake(self.SENTINEL, self.PATTERN, "aws", "d", "HIGH",
                         context_lines=3, ctx_group=0, val_group=None)

    # --- load() -------------------------------------------------------------

    def _base_cfg(self, **over):
        cfg = {
            "name": "aws", "description": "d", "severity": "HIGH",
            "sentinel": self.SENTINEL, "pattern": self.PATTERN,
            "contextLines": 3, "contextgroup": 0, "valgroup": 1,
        }
        cfg.update(over)
        return cfg

    def test_load_builds_rake(self):
        r = SentinelRake.load(self._base_cfg())
        self.assertEqual(r.ptype, "aws")
        self.assertEqual(r.context_lines, 3)
        self.assertEqual(self._feed(r, ["SENTINEL", "secret=abcdef"]),
                         [("abcdef", 2)])

    def test_load_accepts_context_alias(self):
        cfg = self._base_cfg()
        del cfg["contextLines"]
        cfg["context"] = 5
        r = SentinelRake.load(cfg)
        self.assertEqual(r.context_lines, 5)

    def test_load_missing_sentinel_raises(self):
        cfg = self._base_cfg()
        del cfg["sentinel"]
        with self.assertRaises(RuntimeError):
            SentinelRake.load(cfg)

    def test_load_missing_context_lines_raises(self):
        cfg = self._base_cfg()
        del cfg["contextLines"]
        with self.assertRaises(RuntimeError):
            SentinelRake.load(cfg)

    def test_load_missing_groups_raises(self):
        cfg = self._base_cfg()
        del cfg["valgroup"]
        with self.assertRaises(RuntimeError):
            SentinelRake.load(cfg)

    def test_load_with_filters(self):
        r = SentinelRake.load(self._base_cfg(filters=[
            {"type": "literal", "value": "ignoreme"},
        ]))
        hits = self._feed(r, ["SENTINEL", "secret=ignoreme", "secret=keepme"])
        self.assertEqual(hits, [("keepme", 3)])


# ---------------------------------------------------------------------------
# RakeContextPattern
# ---------------------------------------------------------------------------

class TestRakeContextPattern(unittest.TestCase):

    def test_routes_by_extension(self):
        r = RakeContextPattern("test", "desc", "LOW")
        py = RakePattern(r"(py_secret)", "test", "d", "LOW", ctx_group=0)
        js = RakePattern(r"(js_secret)", "test", "d", "LOW", ctx_group=0)
        r.addContext("py", py)
        r.addContext("js", js)

        py_ctx = make_context(filename="x.py")
        js_ctx = make_context(filename="x.js")

        self.assertEqual(len(r.match(py_ctx, "py_secret here")), 1)
        self.assertEqual(len(r.match(py_ctx, "js_secret here")), 0)
        self.assertEqual(len(r.match(js_ctx, "js_secret here")), 1)
        self.assertEqual(len(r.match(js_ctx, "py_secret here")), 0)

    def test_default_context_falls_back(self):
        r = RakeContextPattern("test", "desc", "LOW")
        default = RakePattern(r"(any_secret)", "test", "d", "LOW", ctx_group=0)
        r.addContext(None, default)
        ctx = make_context(filename="weird.xyz")
        self.assertEqual(len(r.match(ctx, "any_secret here")), 1)

    def test_no_match_for_unknown_extension_without_default(self):
        r = RakeContextPattern("test", "desc", "LOW")
        py = RakePattern(r"(py_secret)", "test", "d", "LOW", ctx_group=0)
        r.addContext("py", py)
        ctx = make_context(filename="weird.xyz")
        self.assertEqual(r.match(ctx, "py_secret here"), [])

    def test_duplicate_context_raises(self):
        r = RakeContextPattern("test", "desc", "LOW")
        p1 = RakePattern(r"(a)", "test", "d", "LOW", ctx_group=0)
        p2 = RakePattern(r"(b)", "test", "d", "LOW", ctx_group=0)
        r.addContext("py", p1)
        with self.assertRaises(RuntimeError):
            r.addContext("py", p2)

    def test_load_from_config(self):
        r = RakeContextPattern.load({
            "name": "n", "description": "d", "severity": "LOW",
            "contexts": [
                {"context": ["py"], "pattern": r"(secret)", "contextgroup": 0},
                {"context": "js", "pattern": r"(token)", "contextgroup": 0},
            ],
        })
        self.assertEqual(len(r.match(make_context(filename="x.py"), "secret")), 1)
        self.assertEqual(len(r.match(make_context(filename="x.js"), "token")), 1)
        self.assertEqual(r.match(make_context(filename="x.py"), "token"), [])


# ---------------------------------------------------------------------------
# RakeHostname
# ---------------------------------------------------------------------------

class TestRakeHostname(unittest.TestCase):

    def test_matches_three_part_fqdn(self):
        r = RakeHostname()
        hits = r.match(make_context(), "Visit www.example.com for info")
        self.assertTrue(any(h.value == "www.example.com" for h in hits))

    def test_rejects_unknown_tld(self):
        r = RakeHostname()
        self.assertEqual(r.match(make_context(), "host.sub.notatld"), [])

    def test_two_part_domain_not_matched_by_default(self):
        # The no-domain pattern requires at least 3 parts
        r = RakeHostname()
        self.assertEqual(r.match(make_context(), "just example.com here"), [])

    def test_domain_restriction(self):
        r = RakeHostname(domain="example.com")
        hits = r.match(make_context(), "host.example.com and host.other.com")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "host.example.com")

    def test_isValidHostname_valid(self):
        self.assertTrue(RakeHostname.isValidHostname("foo.example.com"))

    def test_isValidHostname_too_short(self):
        self.assertFalse(RakeHostname.isValidHostname("a"))

    def test_isValidHostname_too_few_parts(self):
        self.assertFalse(RakeHostname.isValidHostname("example.com"))

    def test_isValidHostname_invalid_tld(self):
        self.assertFalse(RakeHostname.isValidHostname("foo.bar.notatld"))

    def test_isValidHostname_label_too_long(self):
        long_label = "x" * 64
        self.assertFalse(
            RakeHostname.isValidHostname(f"{long_label}.example.com"))

    def test_isValidHostname_minparts_override(self):
        self.assertTrue(
            RakeHostname.isValidHostname("example.com", minparts=2))


# ---------------------------------------------------------------------------
# RakeEmail
# ---------------------------------------------------------------------------

class TestRakeEmail(unittest.TestCase):

    def test_matches_basic_email(self):
        r = RakeEmail()
        hits = r.match(make_context(), "contact me at user@example.com please")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "user@example.com")

    def test_domain_restriction(self):
        r = RakeEmail(domain="example.com")
        hits = r.match(make_context(),
                       "valid@example.com bad@other.com")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "valid@example.com")

    def test_rejects_bad_tld(self):
        r = RakeEmail()
        self.assertEqual(r.match(make_context(), "user@example.notatld"), [])


# ---------------------------------------------------------------------------
# RakeBasicAuth
# ---------------------------------------------------------------------------

class TestRakeBasicAuth(unittest.TestCase):

    @staticmethod
    def _encode(s):
        return base64.b64encode(s.encode("utf-8")).decode("ascii")

    def test_matches_valid_basic_auth(self):
        r = RakeBasicAuth()
        token = self._encode("admin:secretpassword123")
        text = f"Authorization: Basic {token}"
        hits = r.match(make_context(), text)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, token)

    def test_rejects_base64_without_colon(self):
        r = RakeBasicAuth()
        token = self._encode("nocolonhere1234567890")
        hits = r.match(make_context(), f"Authorization: Basic {token}")
        self.assertEqual(hits, [])

    def test_rejects_non_printable_decode(self):
        r = RakeBasicAuth()
        raw = bytes(range(0x80, 0x90)) * 2  # 32 bytes of high-bit chars
        token = base64.b64encode(raw).decode("ascii")
        hits = r.match(make_context(), f"Authorization: Basic {token}")
        self.assertEqual(hits, [])

    def test_only_matches_at_end_of_line(self):
        # The b64 regex is anchored to $ — text after the token shouldn't match
        r = RakeBasicAuth()
        token = self._encode("admin:secretpassword123")
        hits = r.match(make_context(),
                       f"Authorization: Basic {token} trailing")
        self.assertEqual(hits, [])


# ---------------------------------------------------------------------------
# RakeJWTAuth
# ---------------------------------------------------------------------------

class TestRakeJWTAuth(unittest.TestCase):

    @staticmethod
    def _b64url(d):
        if isinstance(d, dict):
            d = json.dumps(d).encode()
        return base64.b64encode(d).decode().rstrip("=")

    def _make_token(self, header, payload, signature=None):
        if signature is None:
            signature = "a" * 32
        return f"{self._b64url(header)}.{self._b64url(payload)}.{signature}"

    def test_matches_valid_jwt(self):
        r = RakeJWTAuth()
        token = self._make_token(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890abc", "name": "John Doe"},
        )
        hits = r.match(make_context(), token)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, token)

    def test_rejects_when_header_isnt_json(self):
        r = RakeJWTAuth()
        # base64-decodable but not JSON
        bad_header = self._b64url(b"not-json-at-all-data" * 2)
        good_payload = self._b64url({"sub": "1234567890abc"})
        token = f"{bad_header}.{good_payload}.{'a' * 32}"
        self.assertEqual(r.match(make_context(), token), [])

    def test_rejects_two_part_structure(self):
        # No third dot-separated section — won't match the regex
        r = RakeJWTAuth()
        text = "a" * 32 + "." + "b" * 32
        self.assertEqual(r.match(make_context(), text), [])


# ---------------------------------------------------------------------------
# RakeSet integration
# ---------------------------------------------------------------------------

class TestRakeSet(unittest.TestCase):

    def test_add_dispatches_filemeta_vs_content(self):
        rs = RakeSet()
        meta = RakeFileMeta("m", "d", "LOW", file=r"^foo$", all=False)
        content = RakePattern(r"(secret)", "c", "d", "LOW", ctx_group=0)
        rs.add(meta)
        rs.add(content)
        self.assertIn(meta, rs.meta_rakes)
        self.assertIn(content, rs.content_rakes)

    def test_match_context_returns_filemeta_hits(self):
        rs = RakeSet()
        rs.add(RakeFileMeta("m", "d", "LOW", file=r"^id_rsa$", all=False))
        hits = rs.match_context(make_context(filename="id_rsa"))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].file, "id_rsa")

    def test_match_content_aggregates_hits_from_all_rakes(self):
        rs = RakeSet()
        rs.add(RakePattern(r"(aaa)", "a", "d", "LOW", ctx_group=0))
        rs.add(RakePattern(r"(bbb)", "b", "d", "LOW", ctx_group=0))
        hits = rs.match_content(make_context(), "aaa and bbb")
        self.assertEqual(len(hits), 2)


# ---------------------------------------------------------------------------
# YAML-configured patterns
#
# Tests each rake as it is actually configured in etc/datarake.yaml. These
# are intentionally end-to-end (load -> match), so they catch regressions
# from YAML edits, regex tweaks, and filter changes alike.
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "datarake", "datarake.yaml")


class _YAMLRakesMixin:
    """Shared loading + lookup helpers for YAML-driven tests."""

    @classmethod
    def setUpClass(cls):
        from datarake.__main__ import loadConfig
        cls.rs = loadConfig(CONFIG_PATH)

    def _rake(self, ptype):
        for r in (self.rs.content_rakes + self.rs.meta_rakes):
            if r.ptype == ptype:
                return r
        self.fail(f"rake {ptype!r} not found in YAML config")

    def _content_hits(self, rake, line, ext="txt"):
        return rake.match(make_context(filename=f"x.{ext}", filetype=ext), line)

    def _file_hit(self, rake, filename):
        parts = filename.split(".")
        ext = parts[-1] if len(parts) > 1 else None
        return rake.match(make_context(filename=filename, filetype=ext))


class TestYAMLFileMetaRakes(_YAMLRakesMixin, unittest.TestCase):

    def test_ssh_identity_file(self):
        r = self._rake("ssh identity file")
        for name in ["id_rsa", "id_rsa1", "id_dsa", "id_ecdsa", "id_ed25519"]:
            with self.subTest(positive=name):
                self.assertIsNotNone(self._file_hit(r, name))
        for name in ["id_rsa.pub", "rsa", "id_other", "README", "idrsa"]:
            with self.subTest(negative=name):
                self.assertIsNone(self._file_hit(r, name))

    def test_netrc_file(self):
        r = self._rake("netrc file")
        for name in ["netrc", ".netrc", "foo.netrc"]:
            with self.subTest(positive=name):
                self.assertIsNotNone(self._file_hit(r, name))
        for name in ["netrc.bak", "notnetrc", "README"]:
            with self.subTest(negative=name):
                self.assertIsNone(self._file_hit(r, name))

    def test_pki_file(self):
        r = self._rake("pki file")
        for name in ["cert.pem", "private.key", "client.pfx",
                     "data.p12", "bundle.p7b"]:
            with self.subTest(positive=name):
                self.assertIsNotNone(self._file_hit(r, name))
        for name in ["cert.txt", "notes.md", "README", "key"]:
            with self.subTest(negative=name):
                self.assertIsNone(self._file_hit(r, name))

    def test_java_keystore_file(self):
        r = self._rake("java keystore file")
        for name in ["keystore", "myapp.jks", "app.keystore", "app.ks"]:
            with self.subTest(positive=name):
                self.assertIsNotNone(self._file_hit(r, name))
        for name in ["keystore.bak", "app.txt", "README"]:
            with self.subTest(negative=name):
                self.assertIsNone(self._file_hit(r, name))

    def test_htpasswd_file(self):
        r = self._rake("htpasswd file")
        for name in ["htpasswd", ".htpasswd"]:
            with self.subTest(positive=name):
                self.assertIsNotNone(self._file_hit(r, name))
        for name in ["htpasswd.bak", "passwords.txt", "README"]:
            with self.subTest(negative=name):
                self.assertIsNone(self._file_hit(r, name))


class TestYAMLTokenRake(_YAMLRakesMixin, unittest.TestCase):

    def test_null_context_positive(self):
        r = self._rake("token")
        self.assertEqual(
            len(self._content_hits(r, 'my_token = "abc123secret"', ext="txt")),
            1)

    def test_null_context_negative(self):
        r = self._rake("token")
        for line in ['foo = "bar"', 'tok = "x"', 'random text']:
            with self.subTest(case=line):
                self.assertEqual(self._content_hits(r, line, ext="txt"), [])

    def test_c_family_context(self):
        r = self._rake("token")
        for ext in ["c", "h", "cc", "cpp", "hpp", "cs", "groovy", "java"]:
            with self.subTest(positive_ext=ext):
                self.assertEqual(
                    len(self._content_hits(r, 'mytoken = "abc123secret"', ext=ext)),
                    1)
        for case in [
            'mytoken = "abc"',           # value too short
            'foo = "abc123secret"',      # no "tok" in key
            "mytoken = 'abc123secret'",  # single quotes not allowed in c-family
        ]:
            with self.subTest(negative=case):
                self.assertEqual(self._content_hits(r, case, ext="c"), [])

    def test_js_ts_py_context_positive(self):
        r = self._rake("token")
        self.assertEqual(
            len(self._content_hits(r, 'mytoken = "abc123secret"', ext="py")),
            1)


class TestYAMLPasswordRake(_YAMLRakesMixin, unittest.TestCase):

    def test_null_context_positive(self):
        r = self._rake("password")
        self.assertEqual(
            len(self._content_hits(r, 'password = "secret123"', ext="txt")),
            1)

    def test_null_context_negative(self):
        r = self._rake("password")
        # The regex requires literal "password" (`(w(ord))` is mandatory).
        for line in ['pass = "x"', 'foo = "bar"', 'random text']:
            with self.subTest(case=line):
                self.assertEqual(self._content_hits(r, line, ext="txt"), [])

    def test_c_family_context(self):
        r = self._rake("password")
        for ext in ["c", "h", "cc", "cpp", "hpp", "cs", "groovy", "java"]:
            with self.subTest(positive_ext=ext):
                self.assertEqual(
                    len(self._content_hits(r, 'password = "secret123"', ext=ext)),
                    1)
        for case in [
            'password = "abc"',           # value too short
            'foo = "abc123secret"',       # no "pass" in key
            "password = 'secret123'",     # single quotes not allowed (c-family)
        ]:
            with self.subTest(negative=case):
                self.assertEqual(self._content_hits(r, case, ext="c"), [])

    def test_js_ts_py_context(self):
        r = self._rake("password")
        for ext in ["js", "ts", "py"]:
            with self.subTest(positive_ext=ext):
                self.assertEqual(
                    len(self._content_hits(r, 'password = "secret123"', ext=ext)),
                    1)
                self.assertEqual(
                    len(self._content_hits(r, "password = 'secret123'", ext=ext)),
                    1)
        self.assertEqual(self._content_hits(r, 'password = "abc"', ext="py"), [])

    def test_yaml_context_quoted(self):
        r = self._rake("password")
        for line in ['password: "secret123"', "password: 'secret123'"]:
            with self.subTest(positive=line):
                self.assertEqual(len(self._content_hits(r, line, ext="yaml")), 1)
                self.assertEqual(len(self._content_hits(r, line, ext="yml")), 1)
        for case in ['password: "abc"', 'other: "secret123"']:
            with self.subTest(negative=case):
                self.assertEqual(self._content_hits(r, case, ext="yaml"), [])

    def test_yaml_context_unquoted(self):
        r = self._rake("password")
        self.assertEqual(
            len(self._content_hits(r, "password: secret123", ext="yaml")), 1)

    def test_json_context(self):
        r = self._rake("password")
        self.assertEqual(
            len(self._content_hits(r, '"password": "secret123"', ext="json")),
            1)
        for case in ['"password": "abc"', '"other": "secret123"']:
            with self.subTest(negative=case):
                self.assertEqual(self._content_hits(r, case, ext="json"), [])


class TestYAMLSensitiveEnvRake(_YAMLRakesMixin, unittest.TestCase):

    RAKE_NAME = "sensitive environment variable with default"

    def test_python(self):
        r = self._rake(self.RAKE_NAME)
        positives = [
            "pw = os.getenv('PASSWORD', 'mysecret')",
            'pw = os.getenv("PASSWORD", "mysecret")',
        ]
        for line in positives:
            with self.subTest(positive=line):
                self.assertEqual(len(self._content_hits(r, line, ext="py")), 1)
        negatives = [
            "pw = os.getenv('USER', 'jeff')",         # var name not password
            "pw = os.getenv('PASSWORD')",             # no default value
            "pw = os.getenv('PASSWORD', None)",       # default is not a string
        ]
        for line in negatives:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line, ext="py"), [])

    def test_javascript(self):
        r = self._rake(self.RAKE_NAME)
        positives = [
            ("const pw = process.env.PASSWORD || 'secret';", "js"),
            ('const pw = process.env.PASSWORD ?? "secret";', "ts"),
            ('const pw = process.env["PASSWORD"] || "secret";', "jsx"),
            ("const pw = process.env['PASSWORD'] ?? 'secret';", "tsx"),
        ]
        for line, ext in positives:
            with self.subTest(positive=line, ext=ext):
                self.assertEqual(len(self._content_hits(r, line, ext=ext)), 1)
        negatives = [
            "const pw = process.env.PASSWORD || foo;",     # no quoted default
            "const pw = process.env.PASSWORD;",            # no fallback
            "const pw = process.env.USERNAME || 'jeff';",  # not a password var
        ]
        for line in negatives:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line, ext="js"), [])

    def test_csharp(self):
        r = self._rake(self.RAKE_NAME)
        self.assertEqual(
            len(self._content_hits(
                r,
                'var pw = Environment.GetEnvironmentVariable("PASSWORD") ?? "secret";',
                ext="cs")),
            1)
        negatives = [
            'var pw = Environment.GetEnvironmentVariable("USERNAME") ?? "jeff";',
            'var pw = Environment.GetEnvironmentVariable("PASSWORD");',
        ]
        for line in negatives:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line, ext="cs"), [])

    def test_java(self):
        r = self._rake(self.RAKE_NAME)
        self.assertEqual(
            len(self._content_hits(r, '@Value("${password:mysecret}")', ext="java")),
            1)
        negatives = [
            '@Value("${username:jeff}")',
            '@Value("${password}")',  # no default
        ]
        for line in negatives:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line, ext="java"), [])


class TestYAMLSimplePatternRakes(_YAMLRakesMixin, unittest.TestCase):

    def test_auth_url(self):
        r = self._rake("auth url")
        positives = [
            "https://user:pass@example.com/path",
            "http://admin:secret123@host.example.com",
            "ftp://u:p@server.com",
        ]
        for line in positives:
            with self.subTest(positive=line):
                self.assertEqual(len(self._content_hits(r, line)), 1)
        negatives = [
            "https://example.com",            # no credentials
            "https://example.com/path",       # no credentials
            "user:pass@example.com",          # no scheme
        ]
        for line in negatives:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line), [])

    def test_private_key_positive(self):
        r = self._rake("private key")
        self.assertEqual(
            len(self._content_hits(r, "-----BEGIN RSA PRIVATE KEY-----")),
            1)

    def test_private_key_negative(self):
        r = self._rake("private key")
        for line in [
            "BEGIN PRIVATE KEY",              # missing dashes
            "-----BEGIN private key-----",    # lowercase, regex isn't ignorecase
            "regular text",
        ]:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line), [])

    def test_auth_token_positive(self):
        r = self._rake("auth token")
        for line in [
            "Authorization: Bearer abc123def456ghi789",
            "Authorization: Basic dXNlcjpwYXNzd29yZA==",
        ]:
            with self.subTest(positive=line):
                self.assertEqual(len(self._content_hits(r, line)), 1)

    def test_auth_token_negative(self):
        r = self._rake("auth token")
        for line in [
            "Authorization: Bearer abc",      # token too short
            "Authorization: Token xyz",       # not Basic/Bearer
            "no auth here",
        ]:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line), [])

    def test_sshpass(self):
        r = self._rake("sshpass")
        positives = [
            "sshpass -psecretpw user@host",
            "sshpass -p secretpw user@host",
            "sshpass -p'mypass' user@host",
        ]
        for line in positives:
            with self.subTest(positive=line):
                self.assertEqual(len(self._content_hits(r, line)), 1)
        for line in ["ssh user@host", "echo hello", "passwd reset"]:
            with self.subTest(negative=line):
                self.assertEqual(self._content_hits(r, line), [])


class TestYAMLSentinelRake(_YAMLRakesMixin, unittest.TestCase):

    SENTINEL = "AKIAIOSFODNN7EXAMPLE"                          # access key id
    SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"        # 40-char secret

    def _feed(self, rake, lines, ext="txt"):
        ctx = make_context(filename=f"x.{ext}", filetype=ext)
        hits = []
        for i, line in enumerate(lines, 1):
            ctx["lineno"] = i
            hits.extend(rake.match(ctx, line))
        return [(h.value, h.line) for h in hits]

    def test_secret_with_nearby_access_key_id(self):
        r = self._rake("AWS Secret Access Key")
        hits = self._feed(r, [
            f"aws_access_key_id = {self.SENTINEL}",
            "x", "x",
            f'aws_secret_access_key = "{self.SECRET}"',
        ])
        self.assertEqual(hits, [(self.SECRET, 4)])

    def test_secret_alone_is_not_reported(self):
        # Without the access key ID sentinel, a bare 40-char string is too
        # generic to flag.
        r = self._rake("AWS Secret Access Key")
        self.assertEqual(
            self._feed(r, [f'aws_secret_access_key = "{self.SECRET}"']), [])

    def test_sentinel_after_secret(self):
        r = self._rake("AWS Secret Access Key")
        hits = self._feed(r, [
            f'aws_secret_access_key = "{self.SECRET}"',
            f"aws_access_key_id = {self.SENTINEL}",
        ])
        self.assertEqual(hits, [(self.SECRET, 1)])

    def test_too_far_apart_not_reported(self):
        r = self._rake("AWS Secret Access Key")
        lines = ([f"aws_access_key_id = {self.SENTINEL}"]
                 + ["filler"] * 16
                 + [f'aws_secret_access_key = "{self.SECRET}"'])
        self.assertEqual(self._feed(r, lines), [])


# ---------------------------------------------------------------------------
# FilterRegistry (NamedFilter + FilterSet) — direct unit tests
# ---------------------------------------------------------------------------

class TestFilterRegistry(unittest.TestCase):

    def _named_cfg(self, val):
        return {"type": "regex", "value": val, "ignorecase": False}

    def _make_named(self, val):
        return RakeFilter.load(self._named_cfg(val))

    # --- registration / lookup ----------------------------------------

    def test_register_and_resolve_named_filter(self):
        reg = FilterRegistry()
        f = self._make_named(r"^foo$")
        reg.register_named("MyFilter", f)
        resolved = reg.load({"type": "named", "name": "MyFilter"})
        self.assertIs(resolved, f)

    def test_register_and_expand_filter_set(self):
        reg = FilterRegistry()
        fa = self._make_named(r"^a$")
        fb = self._make_named(r"^b$")
        reg.register_set("Pair", [fa, fb])
        out = reg.load_list([{"type": "set", "name": "Pair"}])
        self.assertEqual(out, [fa, fb])

    def test_filter_set_in_single_load_raises(self):
        reg = FilterRegistry()
        reg.register_set("Pair", [self._make_named(r"^a$")])
        with self.assertRaises(RuntimeError) as cm:
            reg.load({"type": "set", "name": "Pair"})
        self.assertIn("FilterSet", str(cm.exception))

    def test_unknown_named_filter_raises(self):
        reg = FilterRegistry()
        with self.assertRaises(RuntimeError) as cm:
            reg.load({"type": "named", "name": "Nope"})
        self.assertIn("Unknown NamedFilter", str(cm.exception))

    def test_unknown_filter_set_raises(self):
        reg = FilterRegistry()
        with self.assertRaises(RuntimeError) as cm:
            reg.load_list([{"type": "set", "name": "Nope"}])
        self.assertIn("Unknown FilterSet", str(cm.exception))

    def test_named_reference_missing_name_raises(self):
        reg = FilterRegistry()
        with self.assertRaises(RuntimeError):
            reg.load({"type": "named"})

    def test_set_reference_missing_name_raises(self):
        reg = FilterRegistry()
        with self.assertRaises(RuntimeError):
            reg.load_list([{"type": "set"}])

    # --- duplicate / collision handling -------------------------------

    def test_duplicate_named_filter_raises(self):
        reg = FilterRegistry()
        reg.register_named("X", self._make_named(r"^a$"))
        with self.assertRaises(RuntimeError) as cm:
            reg.register_named("X", self._make_named(r"^b$"))
        self.assertIn("Duplicate NamedFilter", str(cm.exception))

    def test_duplicate_filter_set_raises(self):
        reg = FilterRegistry()
        reg.register_set("S", [self._make_named(r"^a$")])
        with self.assertRaises(RuntimeError) as cm:
            reg.register_set("S", [self._make_named(r"^b$")])
        self.assertIn("Duplicate FilterSet", str(cm.exception))

    def test_named_then_set_same_name_raises(self):
        reg = FilterRegistry()
        reg.register_named("X", self._make_named(r"^a$"))
        with self.assertRaises(RuntimeError) as cm:
            reg.register_set("X", [self._make_named(r"^b$")])
        self.assertIn("already used by a NamedFilter", str(cm.exception))

    def test_set_then_named_same_name_raises(self):
        reg = FilterRegistry()
        reg.register_set("X", [self._make_named(r"^a$")])
        with self.assertRaises(RuntimeError) as cm:
            reg.register_named("X", self._make_named(r"^b$"))
        self.assertIn("already used by a FilterSet", str(cm.exception))

    # --- inline-filter compatibility ----------------------------------

    def test_inline_filter_still_works_through_registry(self):
        reg = FilterRegistry()
        f = reg.load({"type": "regex", "value": r"^x$"})
        self.assertIsInstance(f, RakeRegexFilter)

    def test_load_list_preserves_order_across_inline_and_refs(self):
        reg = FilterRegistry()
        n = self._make_named(r"^named$")
        a = self._make_named(r"^a$")
        b = self._make_named(r"^b$")
        reg.register_named("N", n)
        reg.register_set("AB", [a, b])

        out = reg.load_list([
            {"type": "regex", "value": r"^first$"},
            {"type": "named", "name": "N"},
            {"type": "set",   "name": "AB"},
            {"type": "regex", "value": r"^last$"},
        ])
        # 1 inline + 1 named + 2 expanded from set + 1 inline = 5 total
        self.assertEqual(len(out), 5)
        # named filter is the same instance
        self.assertIs(out[1], n)
        # set expanded in place, in order
        self.assertIs(out[2], a)
        self.assertIs(out[3], b)

    def test_named_filter_instance_shared_across_lookups(self):
        # The same RakeFilter instance is returned every time -- safe because
        # filters are read-only after construction.
        reg = FilterRegistry()
        f = self._make_named(r"^x$")
        reg.register_named("N", f)
        a = reg.load({"type": "named", "name": "N"})
        b = reg.load({"type": "named", "name": "N"})
        self.assertIs(a, b)

    # --- RakeFilter.load without a registry ---------------------------

    def test_rakefilter_load_rejects_named_without_registry(self):
        with self.assertRaises(RuntimeError) as cm:
            RakeFilter.load({"type": "named", "name": "X"})
        self.assertIn("FilterRegistry", str(cm.exception))

    def test_rakefilter_load_rejects_set_without_registry(self):
        with self.assertRaises(RuntimeError) as cm:
            RakeFilter.load({"type": "set", "name": "X"})
        self.assertIn("FilterRegistry", str(cm.exception))


# ---------------------------------------------------------------------------
# Rake loaders integrate with FilterRegistry
# ---------------------------------------------------------------------------

class TestRakeLoadWithFilterRegistry(unittest.TestCase):

    def _registry_with_set(self, set_name="Placeholders"):
        reg = FilterRegistry()
        # A pair of regex filters to expand as a set
        f1 = RakeFilter.load({"type": "regex", "value": r"\$\{[A-Z_]+\}"})
        f2 = RakeFilter.load({"type": "regex", "value": r"\{\{\s*[a-z_]+\s*\}\}"})
        reg.register_set(set_name, [f1, f2])
        return reg, [f1, f2]

    def test_rake_pattern_load_expands_set_inline(self):
        reg, [f1, f2] = self._registry_with_set()
        r = RakePattern.load({
            "name": "n", "pattern": r"(token=(\S+))",
            "description": "d", "severity": "LOW",
            "contextgroup": 0, "valgroup": 1,
            "filters": [
                {"type": "set", "name": "Placeholders"},
                {"type": "regex", "value": r"^.{,5}$"},
            ],
        }, filter_registry=reg)
        # 2 from set + 1 inline = 3
        self.assertEqual(len(r.filters), 3)
        self.assertIs(r.filters[0], f1)
        self.assertIs(r.filters[1], f2)

    def test_rake_pattern_load_resolves_named_reference(self):
        reg = FilterRegistry()
        f = RakeFilter.load({"type": "regex", "value": r"^\$\w+$"})
        reg.register_named("DollarVar", f)
        r = RakePattern.load({
            "name": "n", "pattern": r"(token=(\S+))",
            "description": "d", "severity": "LOW",
            "contextgroup": 0, "valgroup": 1,
            "filters": [{"type": "named", "name": "DollarVar"}],
        }, filter_registry=reg)
        self.assertEqual(len(r.filters), 1)
        self.assertIs(r.filters[0], f)

    def test_rake_pattern_load_without_registry_handles_inline(self):
        # Backward compat: no registry, only inline filters work.
        r = RakePattern.load({
            "name": "n", "pattern": r"(token=(\S+))",
            "description": "d", "severity": "LOW",
            "contextgroup": 0, "valgroup": 1,
            "filters": [{"type": "regex", "value": r"^x$"}],
        })
        self.assertEqual(len(r.filters), 1)

    def test_rake_pattern_load_without_registry_rejects_refs(self):
        with self.assertRaises(RuntimeError):
            RakePattern.load({
                "name": "n", "pattern": r"(x)", "description": "d",
                "severity": "LOW", "contextgroup": 0,
                "filters": [{"type": "set", "name": "Placeholders"}],
            })

    def test_rake_context_pattern_load_expands_set(self):
        reg, [f1, f2] = self._registry_with_set()
        rc = RakeContextPattern.load({
            "name": "n", "description": "d", "severity": "LOW",
            "contexts": [
                {
                    "context": ["py"],
                    "pattern": r"(secret=(\S+))",
                    "contextgroup": 0, "valgroup": 1,
                    "filters": [
                        {"type": "set", "name": "Placeholders"},
                        {"type": "regex", "value": r"^short$"},
                    ],
                },
            ],
        }, filter_registry=reg)
        inner = rc.patterns["py"]
        # 2 from set + 1 inline = 3
        self.assertEqual(len(inner.filters), 3)
        self.assertIs(inner.filters[0], f1)
        self.assertIs(inner.filters[1], f2)


# ---------------------------------------------------------------------------
# _buildFilterRegistry parses the YAML FilterRegistry: section correctly
# ---------------------------------------------------------------------------

class TestBuildFilterRegistryFromYAML(unittest.TestCase):

    def _build(self, cfg):
        from datarake.__main__ import _buildFilterRegistry
        return _buildFilterRegistry(cfg)

    def test_builds_named_filter(self):
        reg = self._build({
            "FilterRegistry": [
                {"NamedFilter": [
                    {"name": "Dollar", "type": "regex",
                     "value": r"^\$[a-z]+$", "ignorecase": True},
                ]},
            ],
        })
        self.assertIn("Dollar", reg.named_filters)
        self.assertNotIn("Dollar", reg.filter_sets)

    def test_builds_filter_set_with_split_dicts(self):
        # Matches the YAML the user wrote, where a FilterSet entry is a list
        # carrying name and filters in separate dicts.
        reg = self._build({
            "FilterRegistry": [
                {"FilterSet": [
                    {"name": "S"},
                    {"filters": [
                        {"type": "regex", "value": r"^a$"},
                        {"type": "regex", "value": r"^b$"},
                    ]},
                ]},
            ],
        })
        self.assertIn("S", reg.filter_sets)
        self.assertEqual(len(reg.filter_sets["S"]), 2)

    def test_filter_set_can_reference_earlier_named_filter(self):
        reg = self._build({
            "FilterRegistry": [
                {"NamedFilter": [
                    {"name": "DollarVar", "type": "regex",
                     "value": r"^\$\w+$"},
                ]},
                {"FilterSet": [
                    {"name": "Placeholders"},
                    {"filters": [
                        {"type": "named", "name": "DollarVar"},
                        {"type": "regex", "value": r"\{\{\w+\}\}"},
                    ]},
                ]},
            ],
        })
        self.assertEqual(len(reg.filter_sets["Placeholders"]), 2)
        # The first entry in the set is the same instance as the NamedFilter
        self.assertIs(reg.filter_sets["Placeholders"][0],
                      reg.named_filters["DollarVar"])

    def test_missing_filter_registry_yields_empty_registry(self):
        reg = self._build({})
        self.assertEqual(reg.named_filters, {})
        self.assertEqual(reg.filter_sets, {})

    def test_unknown_kind_raises(self):
        with self.assertRaises(RuntimeError) as cm:
            self._build({"FilterRegistry": [{"Bogus": []}]})
        self.assertIn("Bogus", str(cm.exception))

    def test_named_filter_without_name_raises(self):
        with self.assertRaises(RuntimeError):
            self._build({
                "FilterRegistry": [
                    {"NamedFilter": [{"type": "regex", "value": r"^x$"}]},
                ],
            })

    def test_filter_set_without_name_raises(self):
        with self.assertRaises(RuntimeError):
            self._build({
                "FilterRegistry": [
                    {"FilterSet": [{"filters": []}]},
                ],
            })


# ---------------------------------------------------------------------------
# End-to-end: the real YAML's FilterRegistry actually expands in real rakes
# ---------------------------------------------------------------------------

class TestRealYAMLFilterRegistry(_YAMLRakesMixin, unittest.TestCase):

    def test_named_filter_registered(self):
        # The YAML defines a NamedFilter called ShellVariables. We can't reach
        # it through the rakes (no rake references it currently), so verify
        # via the registry the loadConfig flow produced.
        # _YAMLRakesMixin doesn't expose the registry directly; rebuild here
        # to inspect it.
        from datarake.__main__ import _buildFilterRegistry
        import yaml as _yaml
        with open(CONFIG_PATH) as f:
            cfg = _yaml.safe_load(f)
        reg = _buildFilterRegistry(cfg)
        self.assertIn("ShellVariables", reg.named_filters)
        self.assertIn("VariablesNotLiteral", reg.filter_sets)
        self.assertIn("TestValues", reg.filter_sets)

    def test_password_null_context_set_refs_expanded(self):
        # Password's null context references VariablesNotLiteral and TestValues
        # plus one inline filter. Should produce 3 + 3 + 1 = 7 filters in order.
        r = self._rake("password")
        inner = r.patterns[None]
        self.assertEqual(len(inner.filters), 7)


if __name__ == "__main__":
    unittest.main()
