// Package match holds RakeMatch, the record produced for every finding, plus
// the output-field configuration that controls how it is rendered.
package match

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
)

// RakeInfo is the subset of a Rake that a RakeMatch needs. Declaring it here
// rather than importing the rake package breaks the Rake<->RakeMatch cycle
// that Python resolves with the forward declaration at common.py:13.
type RakeInfo interface {
	PType() string
	PDesc() string
	Severity() string
}

// Field identifies an output column. Order matches common.py:157.
type Field int

const (
	FieldFile Field = iota
	FieldLine
	FieldLabel
	FieldSeverity
	FieldDescription
	FieldKeyOffset
	FieldKeyLength
	FieldKey
	FieldValueOffset
	FieldValueLength
	FieldValue
	FieldContextOffset
	FieldContextLength
	FieldContext
)

var fieldOrder = []Field{
	FieldFile, FieldLine, FieldLabel, FieldSeverity, FieldDescription,
	FieldKeyOffset, FieldKeyLength, FieldKey,
	FieldValueOffset, FieldValueLength, FieldValue,
	FieldContextOffset, FieldContextLength, FieldContext,
}

var fieldNames = map[Field]string{
	FieldFile: "file", FieldLine: "line", FieldLabel: "label",
	FieldSeverity: "severity", FieldDescription: "description",
	FieldKeyOffset: "key_offset", FieldKeyLength: "key_length", FieldKey: "key",
	FieldValueOffset: "value_offset", FieldValueLength: "value_length", FieldValue: "value",
	FieldContextOffset: "context_offset", FieldContextLength: "context_length", FieldContext: "context",
}

// OutputConfig is the immutable replacement for RakeMatch's mutable class
// globals (_secure, _disable_context, _disable_value, _has_been_read, fields).
// Those were written on every attribute read, which is a data race once files
// are scanned concurrently. Built once in main, then read-only.
type OutputConfig struct {
	secure         bool
	disableContext bool
	disableValue   bool
	enabled        map[Field]bool
}

// NewOutputConfig applies the three mutators in the same order main() does
// (secure, then disable_context, then disable_value) because they overlap:
// set_secure enables the context field and a later disable_context must win.
func NewOutputConfig(secure, disableContext, disableValue bool) *OutputConfig {
	o := &OutputConfig{
		secure:         secure,
		disableContext: disableContext,
		disableValue:   disableValue,
		enabled:        make(map[Field]bool, len(fieldOrder)),
	}
	for _, f := range fieldOrder {
		o.enabled[f] = true
	}
	// key_offset, key_length and key default off (common.py:162-164).
	o.enabled[FieldKeyOffset] = false
	o.enabled[FieldKeyLength] = false
	o.enabled[FieldKey] = false

	if secure { // set_secure
		o.enabled[FieldContext] = true
		o.enabled[FieldValue] = false
	}
	if disableContext { // disable_context
		o.enabled[FieldContextOffset] = false
		o.enabled[FieldContextLength] = false
		o.enabled[FieldContext] = false
	}
	if disableValue { // disable_value
		o.enabled[FieldValueOffset] = false
		o.enabled[FieldValueLength] = false
		o.enabled[FieldValue] = false
	}
	return o
}

// PlainOutput is a non-secure, nothing-disabled configuration used when a
// filter or a rake's own Filter needs to inspect a match's real value.
// Filtering runs before output is configured, and a filter must see the actual
// secret to judge it. Safe to share: OutputConfig is immutable after
// construction.
var PlainOutput = NewOutputConfig(false, false, false)

func (o *OutputConfig) Enabled(f Field) bool { return o.enabled[f] }
func (o *OutputConfig) Secure() bool         { return o.secure }
func (o *OutputConfig) DisableContext() bool { return o.disableContext }
func (o *OutputConfig) DisableValue() bool   { return o.disableValue }

// Header returns the enabled column names in output order.
func (o *OutputConfig) Header() []string {
	out := make([]string, 0, len(fieldOrder))
	for _, f := range fieldOrder {
		if o.enabled[f] {
			out = append(out, fieldNames[f])
		}
	}
	return out
}

// span is one of the three (offset, length, value) triples. set distinguishes
// "captured the empty string" from "did not participate", which Python
// represents as "" versus None.
type span struct {
	offset int
	length int
	value  string
	set    bool
}

// RakeMatch records one finding. Offsets and lengths are measured in
// characters (runes), not bytes -- regexp2 indexes in runes, matching Python.
type RakeMatch struct {
	label       string
	description string
	severity    string
	file        string
	line        *int

	key     span
	value   span
	context span

	// MatchGroups mirrors Python's m.groups(default=''): every regex group
	// 1..N, with "" for groups that did not participate. Filters unpack it.
	MatchGroups []string
}

func New(r RakeInfo, file string, line *int) *RakeMatch {
	return &RakeMatch{
		label:       r.PType(),
		description: r.PDesc(),
		severity:    r.Severity(),
		file:        file,
		line:        line,
	}
}

// setSpan stores a triple. A negative length means "derive from value", in
// runes, matching Python's len() on a str.
func setSpan(s *span, v string, offset, length int) {
	if length < 0 {
		length = len([]rune(v))
	}
	*s = span{offset: offset, length: length, value: v, set: true}
}

// SetKey records the key. The key is used almost exclusively for filtering and
// is not output by default.
func (m *RakeMatch) SetKey(v string, offset, length int)     { setSpan(&m.key, v, offset, length) }
func (m *RakeMatch) SetValue(v string, offset, length int)   { setSpan(&m.value, v, offset, length) }
func (m *RakeMatch) SetContext(v string, offset, length int) { setSpan(&m.context, v, offset, length) }

func (m *RakeMatch) File() string        { return m.file }
func (m *RakeMatch) Line() *int          { return m.line }
func (m *RakeMatch) Label() string       { return m.label }
func (m *RakeMatch) Description() string { return m.description }
func (m *RakeMatch) Severity() string    { return m.severity }

func offsetOf(s span) *int {
	if !s.set {
		return nil
	}
	v := s.offset
	return &v
}

func lengthOf(s span) *int {
	if !s.set {
		return nil
	}
	v := s.length
	return &v
}

func (m *RakeMatch) Key() *string {
	if !m.key.set {
		return nil
	}
	v := m.key.value
	return &v
}
func (m *RakeMatch) KeyOffset() *int { return offsetOf(m.key) }
func (m *RakeMatch) KeyLength() *int { return lengthOf(m.key) }

func (m *RakeMatch) ValueOffset() *int { return offsetOf(m.value) }
func (m *RakeMatch) ValueLength() *int { return lengthOf(m.value) }

// Value returns nil in secure mode so no secret is ever rendered.
func (m *RakeMatch) Value(o *OutputConfig) *string {
	if o.Secure() || !m.value.set {
		return nil
	}
	v := m.value.value
	return &v
}

func (m *RakeMatch) ContextOffset() *int { return offsetOf(m.context) }
func (m *RakeMatch) ContextLength() *int { return lengthOf(m.context) }

// Context returns the md5 tracking hash instead of the literal text in secure
// mode, so a secret can still be followed as it moves within a file.
func (m *RakeMatch) Context(o *OutputConfig) *string {
	if !m.context.set {
		return nil
	}
	if o.Secure() {
		v := m.SecureContext()
		return &v
	}
	v := m.context.value
	return &v
}

// SecureContext hashes the file name and the literal context together.
func (m *RakeMatch) SecureContext() string {
	if !m.context.set {
		return ""
	}
	h := md5.New()
	h.Write([]byte(m.file))
	h.Write([]byte{0x00})
	h.Write([]byte(m.context.value))
	return hex.EncodeToString(h.Sum(nil))
}

// AsRecord renders the enabled fields in order for CSV. A nil value becomes
// the empty field, matching how csv.writer renders Python's None.
func (m *RakeMatch) AsRecord(o *OutputConfig) []string {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	num := func(p *int) string {
		if p == nil {
			return ""
		}
		return strconv.Itoa(*p)
	}

	out := make([]string, 0, len(fieldOrder))
	for _, f := range fieldOrder {
		if !o.enabled[f] {
			continue
		}
		switch f {
		case FieldFile:
			out = append(out, m.file)
		case FieldLine:
			out = append(out, num(m.line))
		case FieldLabel:
			out = append(out, m.label)
		case FieldSeverity:
			out = append(out, m.severity)
		case FieldDescription:
			out = append(out, m.description)
		case FieldKeyOffset:
			out = append(out, num(m.KeyOffset()))
		case FieldKeyLength:
			out = append(out, num(m.KeyLength()))
		case FieldKey:
			out = append(out, str(m.Key()))
		case FieldValueOffset:
			out = append(out, num(m.ValueOffset()))
		case FieldValueLength:
			out = append(out, num(m.ValueLength()))
		case FieldValue:
			out = append(out, str(m.Value(o)))
		case FieldContextOffset:
			out = append(out, num(m.ContextOffset()))
		case FieldContextLength:
			out = append(out, num(m.ContextLength()))
		case FieldContext:
			if o.DisableContext() {
				out = append(out, "")
				continue
			}
			out = append(out, str(m.Context(o)))
		}
	}
	return out
}

// Equal mirrors RakeMatch.__eq__: offsets and values of value/context must
// agree, as must label, description, severity, file and line. Lengths are
// deliberately not compared (common.py:219,226).
func (m *RakeMatch) Equal(other *RakeMatch) bool {
	if other == nil {
		return false
	}
	eqSpan := func(a, b span) bool {
		if a.set != b.set {
			return false
		}
		if !a.set {
			return true
		}
		return a.offset == b.offset && a.value == b.value
	}
	if !eqSpan(m.value, other.value) || !eqSpan(m.context, other.context) {
		return false
	}
	if m.label != other.label || m.description != other.description ||
		m.severity != other.severity || m.file != other.file {
		return false
	}
	switch {
	case m.line == nil && other.line == nil:
		return true
	case m.line == nil || other.line == nil:
		return false
	default:
		return *m.line == *other.line
	}
}
