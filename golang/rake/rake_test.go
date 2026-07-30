package rake

import "testing"

func TestNewRakeRejectsInvalidPart(t *testing.T) {
	if _, err := NewRake("X", "t", "d", "LOW", "bogus"); err == nil {
		t.Error("an invalid part must be rejected")
	}
	for _, p := range []string{PartContent, PartFileMeta} {
		if _, err := NewRake("X", "t", "d", "LOW", p); err != nil {
			t.Errorf("part %q must be accepted: %v", p, err)
		}
	}
}

func TestRakeAccessors(t *testing.T) {
	r, err := NewRake("RakePattern", "password", "possible plaintext password", "HIGH", PartContent)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name() != "RakePattern" || r.PType() != "password" ||
		r.PDesc() != "possible plaintext password" || r.Severity() != "HIGH" ||
		r.Part() != PartContent {
		t.Errorf("accessor mismatch: %#v", r)
	}
}

func TestRakeString(t *testing.T) {
	r, _ := NewRake("RakePattern", "password", "d", "HIGH", PartContent)
	want := "<Rake(RakePattern, password, content)>"
	if got := r.String(); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRelPathStripsBasepathAndLeadingSlashes(t *testing.T) {
	cases := []struct{ base, full, want string }{
		{"/src", "/src/a/b.txt", "a/b.txt"},
		{"/src", "/src///a.txt", "a.txt"},
		{"", "a.txt", "a.txt"},
		{".", "./a.txt", "a.txt"},
		// Hardening: Python raises IndexError here (common.py:121).
		{"/src", "/src", ""},
		{"/src", "/src/", ""},
	}
	for _, tc := range cases {
		if got := RelPath(tc.base, tc.full); got != tc.want {
			t.Errorf("RelPath(%q,%q): got %q want %q", tc.base, tc.full, got, tc.want)
		}
	}
}
