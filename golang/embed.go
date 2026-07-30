// Package datarake embeds the default scanner configuration.
package datarake

import _ "embed"

// DefaultConfig is the configuration used when no -c/--config is supplied.
// It replaces the Python importlib.resources lookup in _default_config_text.
//
//go:embed datarake.yaml
var DefaultConfig []byte
