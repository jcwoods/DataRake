// Package config loads the YAML configuration and builds the RakeSet.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jcwoods/datarake/golang/filter"
	"github.com/jcwoods/datarake/golang/rake"
	"github.com/jcwoods/datarake/golang/rakeset"
	"github.com/jcwoods/datarake/golang/walker"
)

// Global mirrors the config's Global: section.
//
// CommonTLDs is honored by rake.NewHostname and rake.NewEmail. The other three
// have no counterpart anywhere in the Python -- no code path consumes them or
// anything equivalent -- so they are parsed and reserved rather than wired to
// behavior. Implementing them would add suppression semantics that have never
// existed, which is a feature rather than a port.
type Global struct {
	IgnorePasswords []string // reserved; no behavior
	IgnoreUsers     []string // reserved; no behavior
	IgnoreHosts     []string // reserved; no behavior
	CommonTLDs      []string
}

// WalkerConfig mirrors the config's DirectoryWalker: section. Both keys are
// honored here; in Python they are parsed by nobody and the equivalent values
// sit hardcoded in DirectoryWalker.__init__ and RakeSet.DEFAULT_BLACKLIST.
type WalkerConfig struct {
	ExcludeSubdirs        []string
	ExcludeFileExtensions []string
}

// Config is a loaded configuration.
type Config struct {
	Verbose bool
	Global  Global
	Walker  WalkerConfig
	RakeSet *rakeset.RakeSet
}

// walkerDefaults returns the hardcoded ExcludeSubdirs default.
func walkerDefaults() []string { return walker.DefaultExcludeSubdirs }

// yamlFile mirrors the on-disk schema. Pointers distinguish "key absent" (use
// the default) from "key present but empty" (exclude nothing).
type yamlFile struct {
	Verbose bool `yaml:"verbose"`

	Global *struct {
		IgnorePasswords []string  `yaml:"IgnorePasswords"`
		IgnoreUsers     []string  `yaml:"IgnoreUsers"`
		IgnoreHosts     []string  `yaml:"IgnoreHosts"`
		CommonTLDs      *[]string `yaml:"CommonTLDs"`
	} `yaml:"Global"`

	DirectoryWalker *struct {
		ExcludeSubdirs        *[]string `yaml:"ExcludeSubdirs"`
		ExcludeFileExtensions *[]string `yaml:"ExcludeFileExtensions"`
	} `yaml:"DirectoryWalker"`

	FilterRegistry []map[string][]map[string]any `yaml:"FilterRegistry"`
	Rakes          []map[string]any              `yaml:"Rakes"`
}

// LoadFile reads and parses a configuration file.
func LoadFile(path string, timeout time.Duration) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Load(data, timeout)
}

// Load parses configuration bytes and builds the RakeSet.
func Load(data []byte, timeout time.Duration) (*Config, error) {
	var f yamlFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg := &Config{Verbose: f.Verbose}

	// Global.
	cfg.Global.CommonTLDs = rake.DefaultTLDs
	if f.Global != nil {
		cfg.Global.IgnorePasswords = f.Global.IgnorePasswords
		cfg.Global.IgnoreUsers = f.Global.IgnoreUsers
		cfg.Global.IgnoreHosts = f.Global.IgnoreHosts
		if f.Global.CommonTLDs != nil {
			cfg.Global.CommonTLDs = *f.Global.CommonTLDs
		}
	}

	// DirectoryWalker.
	cfg.Walker.ExcludeSubdirs = walkerDefaults()
	cfg.Walker.ExcludeFileExtensions = rakeset.DefaultExcludeExtensions
	if f.DirectoryWalker != nil {
		if f.DirectoryWalker.ExcludeSubdirs != nil {
			cfg.Walker.ExcludeSubdirs = *f.DirectoryWalker.ExcludeSubdirs
		}
		if f.DirectoryWalker.ExcludeFileExtensions != nil {
			cfg.Walker.ExcludeFileExtensions = *f.DirectoryWalker.ExcludeFileExtensions
		}
	}

	// The registry must be built first so rake filter references resolve.
	reg, err := buildFilterRegistry(f.FilterRegistry, timeout)
	if err != nil {
		return nil, err
	}

	rs := rakeset.New(cfg.Verbose, cfg.Walker.ExcludeFileExtensions)
	for _, r := range f.Rakes {
		if err := addRake(rs, r, reg, timeout); err != nil {
			return nil, err
		}
	}
	cfg.RakeSet = rs

	return cfg, nil
}

// addRake builds one rake and files it into the set.
func addRake(rs *rakeset.RakeSet, r map[string]any, reg *filter.FilterRegistry, timeout time.Duration) error {
	t, _ := r["type"].(string)

	switch t {
	case "ContextPattern":
		cp, err := rake.LoadContextPattern(r, reg, timeout)
		if err != nil {
			return err
		}
		return rs.Add(cp)

	case "FileMeta":
		// FileMeta configures no filters today, so it takes no registry.
		fm, err := rake.LoadFileMeta(r, timeout)
		if err != nil {
			return err
		}
		return rs.Add(fm)

	case "SimplePattern":
		p, err := rake.LoadPattern(r, reg, timeout)
		if err != nil {
			return err
		}
		return rs.Add(p)

	default:
		return fmt.Errorf("unsupported Rake type: %s", t)
	}
}

// buildFilterRegistry constructs the registry from the FilterRegistry section.
//
// The section is a list of single-key mappings:
//
//	- NamedFilter:
//	    - name: X
//	      type: regex
//	      ...
//	- FilterSet:
//	  - name: Y
//	  - filters: [ ... ]
//
// NamedFilter items are complete filter definitions plus a name. FilterSet
// items split the name and the filter list across separate entries, which are
// merged here.
func buildFilterRegistry(entries []map[string][]map[string]any, timeout time.Duration) (*filter.FilterRegistry, error) {
	reg := filter.NewFilterRegistry()

	for _, entry := range entries {
		if len(entry) != 1 {
			return nil, fmt.Errorf(
				"FilterRegistry entries must be single-key mappings (NamedFilter or FilterSet); got %d keys", len(entry))
		}

		for kind, items := range entry {
			switch kind {
			case "NamedFilter":
				for _, item := range items {
					name, ok := item["name"].(string)
					if !ok {
						return nil, fmt.Errorf("NamedFilter entry missing 'name'")
					}
					// Everything except the name is the filter definition.
					def := make(map[string]any, len(item))
					for k, v := range item {
						if k == "name" {
							continue
						}
						def[k] = v
					}
					f, err := filter.Load(def, timeout)
					if err != nil {
						return nil, fmt.Errorf("NamedFilter %q: %w", name, err)
					}
					if err := reg.RegisterNamed(name, f); err != nil {
						return nil, err
					}
				}

			case "FilterSet":
				merged := map[string]any{}
				for _, item := range items {
					for k, v := range item {
						merged[k] = v
					}
				}
				name, ok := merged["name"].(string)
				if !ok {
					return nil, fmt.Errorf("FilterSet entry missing 'name'")
				}
				raw, _ := merged["filters"].([]any)
				filters, err := reg.LoadList(raw, timeout)
				if err != nil {
					return nil, fmt.Errorf("FilterSet %q: %w", name, err)
				}
				if err := reg.RegisterSet(name, filters); err != nil {
					return nil, err
				}

			default:
				return nil, fmt.Errorf("unknown FilterRegistry entry kind: %q", kind)
			}
		}
	}

	return reg, nil
}
