//go:build !console

// Package console embeds the built Vue console (npm run build) when compiled
// with -tags console; without the tag the service serves no console.
package console

import "io/fs"

// Dist reports that no console is embedded in this build.
func Dist() (fs.FS, bool) { return nil, false }

// Remote reports that no federated remote is embedded in this build.
func Remote() (fs.FS, bool) { return nil, false }
