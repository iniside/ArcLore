// Package web bundles the static assets and generated templates for ArcLoreWeb.
package web

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed static
var StaticFS embed.FS

// StaticHandler serves the embedded static assets under /static/* with a long
// immutable cache lifetime (assets are content-stable; bust by filename).
func StaticHandler() http.Handler {
	sub, err := fs.Sub(StaticFS, "static")
	if err != nil {
		// embed.FS guarantees "static" exists at build time; a failure here is a
		// programming error, not a runtime condition.
		log.Fatalf("arcloreweb: static embed: %v", err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.StripPrefix("/static/", fileServer).ServeHTTP(w, r)
	})
}
