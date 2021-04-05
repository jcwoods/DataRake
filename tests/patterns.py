import unittest
from datarake import RakeHostname, RakeMatch
from datarake import RakeURL
from datarake import RakeMatch

class RakeTestResult(object):
    '''
    In terms of attributes, a close mirror of the RakeMatch class, but includes
    a comparison operator required for assertions and less display logic.
    '''

    def __init__(self, val = None,
                       val_off = None,
                       val_len = None,
                       ctx = None,
                       ctx_off = None,
                       ctx_len = None):

        self._value = val
        self._value_offset = val_off
        self._value_length = val_len if val_len is not None else len(val)
        self._context = ctx
        self._context_offset = ctx_off
        self._context_length = ctx_len if ctx_len is not None else len(ctx)
        return

    def __str__(self):
        val = str(self._value)
        val_off = self._value_offset
        val_len = self._value_length
        v = "value=\"{val}\" ({val_off}->{val_len})"

        ctx = str(self._context)
        ctx_off = self._context_offset
        ctx_len = self._context_length
        c = "context=\"{ctx}\" ({ctx_off}->{ctx_len})"
        return f"<RakeTestResult: {v} {c}>"

    def __eq__(self, rm:RakeMatch):
        # Note that we're not checking context (file, line), desc, severity
        if self._value != rm.value: return False
        if self._value_offset != rm.value_offset: return False
        if self._value_length != rm.value_length: return False
        if self._context != rm.context: return False
        if self._context_offset != rm.context_offset: return False
        if self._context_length != rm.context_length: return False
        return True

class RakeTestCase(object):
    def __init__(self, text:str = None,
                       context:dict = None,
                       result:RakeTestResult = None):

        self._text = text
        self._context = context
        self._result = result

        return

    def __str__(self):
        t = str(self._text)
        c = str(self._context)
        return f"<RakeTestCase: text=\"{t}\", context=\"{c}\" >"

    def getContext(self):
        return self._context

    def getText(self):
        return self._text

class TestRakeURL(unittest.TestCase):

    generic_context = { "basepath": "/fake/path",
                        "fullpath": "/fake/path/to/file.txt",
                        "path":     "to/file.txt",
                        "filename": "file.txt",
                        "filetype": "txt",
                        "lineno":   777 }

    testcases = [  # this case should pass with a hit on 'docs.datarake.com'
                   RakeTestCase("Use http://jim:Sup3rSekret!@my.host.com for access",
                                generic_context,
                                RakeTestResult(val = "jim:Sup3rSekret!",
                                               val_off = 11,
                                               ctx = "http://jim:Sup3rSekret!@my.host.com",
                                               ctx_off = 4) ),

                   # this case should be filtered (empty set) for common domain
                   RakeTestCase("Use http://jim:Sup3rSekret!@my.example.com for access",
                                 generic_context,
                                 None),

                   # this case should be filtered (empty set) for user/password
                   RakeTestCase("Use http://jim:Sup3rSekret!@my.example.com for access",
                                 generic_context,
                                 None),

                   # this case should be return empty set
                   RakeTestCase("Go to my doc site for more information",
                                 generic_context,
                                 None) ]

    def test_match(self):
        for tc in TestRakeHostname.testcases:
            context = tc.getContext()
            text = tc.getText()
            rake = RakeURL()

            print(f"* Rake:{rake.ptype} :: {text}")
            matches = list(rake.match(context, text))
            print(matches[0] if len(matches) > 0 else None)
            if len(matches) == 0:
                print("***")
                print(matches)
                self.assertTrue(tc._result is None)
            else:
                self.assertTrue(tc._result == matches[0])

        return
                    

class TestRakeHostname(unittest.TestCase):

    generic_context = { "basepath": "/fake/path",
                        "fullpath": "/fake/path/to/file.txt",
                        "path":     "to/file.txt",
                        "filename": "file.txt",
                        "filetype": "txt",
                        "lineno":   777 }

    testcases = [  # this case should pass with a hit on 'docs.datarake.com'
                   RakeTestCase("Go to docs.datarake.com for more information",
                                generic_context,
                                RakeTestResult(val = "docs.datarake.com",
                                               val_off = 6,
                                               val_len = 17,
                                               ctx = "docs.datarake.com",
                                               ctx_off = 6,
                                               ctx_len = 17,) ),

                   # this case should be filtered (empty set) for invalid TLD
                   RakeTestCase("Go to docs.datarake.www for more information",
                                generic_context,
                                None),

                   # this case should be return empty set
                   RakeTestCase("Go to my doc site for more information",
                                generic_context,
                                None) ]

    def test_match(self):
        for tc in TestRakeHostname.testcases:
            context = tc.getContext()
            text = tc.getText()
            rake = RakeHostname()

            matches = list(rake.match(context, text))
            if len(matches) == 0:
                self.assertTrue(tc._result is None)
            else:
                self.assertTrue(tc._result == matches[0])

        return
                    

if __name__ == "__main__":
    unittest.main()
