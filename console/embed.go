//go:build console

// Package console embeds the built Vue console (npm run build) when compiled
// with -tags console; without the tag the service serves no console.
package console

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

//go:embed all:dist-remote
var distRemote embed.FS

// Dist is the built console rooted at dist/.
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}

// Remote is the federated remote build (npm run build:remote) rooted at
// dist-remote/, served by the auth service under /ui/ in gateway mode.
func Remote() (fs.FS, bool) {
	sub, err := fs.Sub(distRemote, "dist-remote")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "mf-manifest.json"); err != nil {
		return nil, false
	}
	return sub, true
}
