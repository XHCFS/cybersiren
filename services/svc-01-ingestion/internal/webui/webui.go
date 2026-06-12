// Package webui embeds the svc-01 demo single-page UI so it is served straight
// from the binary, independent of the process working directory. Serving from a
// CWD-relative ./static path 404s whenever the service is launched from the repo
// root (e.g. scripts/dev/run_pipeline.sh) rather than its own service dir;
// embedding removes that footgun and ships the demo inside the binary.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed assets
var embedded embed.FS

// FS returns the demo UI asset tree rooted at the assets directory
// (assets/index.html, plus any future split-out CSS/JS). Serve it with
// http.ServeFileFS / http.FileServerFS.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "assets")
	if err != nil {
		// The embed path is a compile-time constant, so this is unreachable.
		panic("webui: embed sub failed: " + err.Error())
	}
	return sub
}
