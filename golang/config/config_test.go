package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/rakeset"
)

func loadYAML(t *testing.T, body string) *Config {
	t.Helper()
	c, err := Load([]byte(body), time.Second)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestLoadDispatchesAllThreeRakeTypes(t *testing.T) {
	c := loadYAML(t, `
Rakes:
- name: meta
  type: FileMeta
  description: d
  severity: HIGH
  file: "^id_rsa$"
- name: simple
  type: SimplePattern
  description: d
  severity: HIGH
  pattern: '((\w+)=(\w+))'
  contextgroup: 0
  valgroup: 2
- name: ctx
  type: ContextPattern
  description: d
  severity: LOW
  contexts:
  - context: null
    pattern: '((\w+):(\w+))'
    contextgroup: 0
    valgroup: 2
`)
	if got := c.RakeSet.MetaCount(); got != 1 {
		t.Errorf("meta rakes: got %d want 1", got)
	}
	if got := c.RakeSet.ContentCount(); got != 2 {
		t.Errorf("content rakes: got %d want 2", got)
	}
}

func TestLoadRejectsUnsupportedRakeType(t *testing.T) {
	_, err := Load([]byte(`
Rakes:
- name: x
  type: NotARakeType
  description: d
  severity: LOW
`), time.Second)
	if err == nil {
		t.Error("an unsupported rake type must error")
	}
}

func TestLoadReadsVerbose(t *testing.T) {
	if c := loadYAML(t, "verbose: true\nRakes: []\n"); !c.Verbose {
		t.Error("verbose must be read from the config")
	}
	if c := loadYAML(t, "Rakes: []\n"); c.Verbose {
		t.Error("verbose must default to false")
	}
}

func TestNamedFilterRegistryResolves(t *testing.T) {
	c := loadYAML(t, `
FilterRegistry:
- NamedFilter:
    - name:       ShellVariables
      type:       regex
      key:        null
      value:      '^\$[a-z0-9_]+$'
      ignorecase: true
Rakes:
- name: simple
  type: SimplePattern
  description: d
  severity: HIGH
  pattern: '((\w+)=(\S+))'
  contextgroup: 0
  valgroup: 2
  filters:
  - type: named
    name: ShellVariables
`)
	if c.RakeSet.ContentCount() != 1 {
		t.Fatal("expected one content rake")
	}
}

func TestFilterSetSplitAcrossListEntriesIsMerged(t *testing.T) {
	// The shipped schema splits a FilterSet's name and filters into separate
	// list entries; they must be merged.
	c := loadYAML(t, `
FilterRegistry:
- FilterSet:
  - name: VariablesNotLiteral
  - filters:
    - type:       regex
      key:        null
      value:      '^\$[a-z0-9_]+$'
      ignorecase: true
    - type:       regex
      key:        null
      value:      '^\{\{\s*[a-z0-9_]+\s*\}\}$'
      ignorecase: true
Rakes:
- name: simple
  type: SimplePattern
  description: d
  severity: HIGH
  pattern: '((\w+)=(\S+))'
  contextgroup: 0
  valgroup: 2
  filters:
  - type: set
    name: VariablesNotLiteral
`)
	if c.RakeSet.ContentCount() != 1 {
		t.Fatal("expected one content rake")
	}
}

func TestUnknownFilterRegistryKindErrors(t *testing.T) {
	_, err := Load([]byte(`
FilterRegistry:
- SomethingElse:
    - name: x
Rakes: []
`), time.Second)
	if err == nil {
		t.Error("an unknown FilterRegistry kind must error")
	}
}

func TestFilterRegistryEntriesMustBeSingleKey(t *testing.T) {
	_, err := Load([]byte(`
FilterRegistry:
- NamedFilter:
    - name: a
      type: literal
      value: x
  FilterSet:
    - name: b
Rakes: []
`), time.Second)
	if err == nil {
		t.Error("a multi-key FilterRegistry entry must error")
	}
}

func TestDirectoryWalkerSectionIsHonored(t *testing.T) {
	c := loadYAML(t, `
DirectoryWalker:
  ExcludeSubdirs: [ '.git', '__pycache__' ]
  ExcludeFileExtensions: [ 'doc', 'xls' ]
Rakes: []
`)
	if len(c.Walker.ExcludeSubdirs) != 2 || c.Walker.ExcludeSubdirs[0] != ".git" {
		t.Errorf("ExcludeSubdirs: %#v", c.Walker.ExcludeSubdirs)
	}
	if len(c.Walker.ExcludeFileExtensions) != 2 {
		t.Errorf("ExcludeFileExtensions: %#v", c.Walker.ExcludeFileExtensions)
	}
}

// An absent section must fall back to the hardcoded Python defaults.
func TestAbsentSectionsUseDefaults(t *testing.T) {
	c := loadYAML(t, "Rakes: []\n")
	if len(c.Walker.ExcludeSubdirs) != len(walkerDefaults()) {
		t.Errorf("absent ExcludeSubdirs must default to %v, got %v",
			walkerDefaults(), c.Walker.ExcludeSubdirs)
	}
	if len(c.Walker.ExcludeFileExtensions) != len(rakeset.DefaultExcludeExtensions) {
		t.Errorf("absent ExcludeFileExtensions must default to DEFAULT_BLACKLIST, got %v",
			c.Walker.ExcludeFileExtensions)
	}
	if len(c.Global.CommonTLDs) != len(rake.DefaultTLDs) {
		t.Errorf("absent CommonTLDs must default to DefaultTLDs, got %v", c.Global.CommonTLDs)
	}
}

// An explicitly empty list means "exclude nothing", not "use the defaults".
func TestEmptyListIsHonoredNotDefaulted(t *testing.T) {
	c := loadYAML(t, `
DirectoryWalker:
  ExcludeSubdirs: []
  ExcludeFileExtensions: []
Rakes: []
`)
	if c.Walker.ExcludeSubdirs == nil || len(c.Walker.ExcludeSubdirs) != 0 {
		t.Errorf("an explicit empty list must be preserved, got %#v", c.Walker.ExcludeSubdirs)
	}
	if c.Walker.ExcludeFileExtensions == nil || len(c.Walker.ExcludeFileExtensions) != 0 {
		t.Errorf("an explicit empty list must be preserved, got %#v", c.Walker.ExcludeFileExtensions)
	}
}

func TestGlobalCommonTLDsIsHonored(t *testing.T) {
	c := loadYAML(t, `
Global:
  CommonTLDs: [ 'com', 'net' ]
Rakes: []
`)
	if len(c.Global.CommonTLDs) != 2 {
		t.Errorf("CommonTLDs: %#v", c.Global.CommonTLDs)
	}
}

// These three have no hardcoded Python counterpart, so they are parsed and
// reserved rather than wired to behavior.
func TestReservedGlobalKeysAreParsed(t *testing.T) {
	c := loadYAML(t, `
Global:
  IgnorePasswords: [ 'password' ]
  IgnoreUsers:     [ 'example', 'user' ]
  IgnoreHosts:     [ 'example', 'domain' ]
Rakes: []
`)
	if len(c.Global.IgnorePasswords) != 1 || len(c.Global.IgnoreUsers) != 2 || len(c.Global.IgnoreHosts) != 2 {
		t.Errorf("reserved keys must still be parsed: %#v", c.Global)
	}
}

func TestLoadFileReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("Rakes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yaml"), time.Second); err == nil {
		t.Error("a missing config file must error")
	}
}

func TestLoadInvalidYAMLErrors(t *testing.T) {
	if _, err := Load([]byte("Rakes: [ unclosed"), time.Second); err == nil {
		t.Error("invalid YAML must error")
	}
}
