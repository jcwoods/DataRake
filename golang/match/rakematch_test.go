package match

import "testing"

type fakeRake struct{ t, d, s string }

func (f fakeRake) PType() string    { return f.t }
func (f fakeRake) PDesc() string    { return f.d }
func (f fakeRake) Severity() string { return f.s }

func intp(i int) *int { return &i }

func TestDefaultHeaderOrderAndDisabledKeyFields(t *testing.T) {
	o := NewOutputConfig(false, false, false)
	want := []string{
		"file", "line", "label", "severity", "description",
		"value_offset", "value_length", "value",
		"context_offset", "context_length", "context",
	}
	got := o.Header()
	if len(got) != len(want) {
		t.Fatalf("header len: got %d %v want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("header[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSecureThenDisableContextOrdering(t *testing.T) {
	// set_secure enables the context field; a later disable_context must win.
	o := NewOutputConfig(true, true, false)
	if o.Enabled(FieldContext) {
		t.Error("disable_context must override set_secure's fields['context']=True")
	}
	if o.Enabled(FieldValue) {
		t.Error("secure mode must disable the value field")
	}
}

func TestSecureModeContextIsHash(t *testing.T) {
	o := NewOutputConfig(true, false, false)
	m := New(fakeRake{"password", "desc", "HIGH"}, "a/b.txt", intp(2))
	m.SetContext("password=hunter2", 0, 16)
	got := m.Context(o)
	if got == nil {
		t.Fatal("context must be present in secure mode")
	}
	if len(*got) != 32 {
		t.Errorf("secure context must be a 32-char md5 hex digest, got %q", *got)
	}
	if *got == "password=hunter2" {
		t.Error("secure mode leaked the plaintext context")
	}
}

func TestAsRecordRendersNilAsEmptyAndIntsAsDigits(t *testing.T) {
	o := NewOutputConfig(false, false, false)
	// filemeta matches carry no line and no value/context.
	m := New(fakeRake{"ssh identity file", "d", "HIGH"}, "id_rsa", nil)
	rec := m.AsRecord(o)
	if rec[0] != "id_rsa" {
		t.Errorf("file: got %q", rec[0])
	}
	if rec[1] != "" {
		t.Errorf("nil line must render as empty string, got %q", rec[1])
	}
	m2 := New(fakeRake{"password", "d", "HIGH"}, "f", intp(7))
	m2.SetValue("hunter2", 9, 7)
	rec2 := m2.AsRecord(o)
	if rec2[1] != "7" {
		t.Errorf("line: got %q want \"7\"", rec2[1])
	}
	if rec2[5] != "9" || rec2[6] != "7" || rec2[7] != "hunter2" {
		t.Errorf("value triple: got %q,%q,%q", rec2[5], rec2[6], rec2[7])
	}
}

func TestUnsetGroupsReturnNil(t *testing.T) {
	o := NewOutputConfig(false, false, false)
	m := New(fakeRake{"t", "d", "LOW"}, "f", intp(1))
	if m.Value(o) != nil || m.ValueOffset() != nil || m.ValueLength() != nil {
		t.Error("unset value must report nil, not zero")
	}
	if m.Key() != nil {
		t.Error("unset key must report nil")
	}
	if m.SecureContext() != "" {
		t.Error("SecureContext with no context must be empty")
	}
}

func TestSetKeyLengthDefaultsToRuneLength(t *testing.T) {
	m := New(fakeRake{"t", "d", "LOW"}, "f", intp(1))
	m.SetKey("héllo", 3, -1) // -1 means "derive from the value"
	if got := m.KeyLength(); got == nil || *got != 5 {
		t.Errorf("length must be in runes (5), got %v", got)
	}
}

func TestPlainOutputExposesValueAndContext(t *testing.T) {
	m := New(fakeRake{"t", "d", "LOW"}, "f", intp(1))
	m.SetValue("hunter2", 0, -1)
	m.SetContext("pw=hunter2", 0, -1)
	if v := m.Value(PlainOutput); v == nil || *v != "hunter2" {
		t.Errorf("PlainOutput must expose the real value, got %v", v)
	}
	if v := m.Context(PlainOutput); v == nil || *v != "pw=hunter2" {
		t.Errorf("PlainOutput must expose the real context, got %v", v)
	}
}
