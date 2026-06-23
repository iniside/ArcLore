// Package render turns repository content (markdown READMEs, source files,
// diffs) into templ components for the browse UI. Step 4 introduces markdown
// rendering and the shared chroma class-mode stylesheet; later steps extend it
// with file highlighting and diff rendering.
package render

import (
	"bytes"

	"github.com/a-h/templ"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting/v2"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

// chromaStyle is the chroma style whose class-mode CSS is emitted by
// GenerateCSS and referenced by the highlighted code blocks goldmark produces.
// It is shared between markdown code fences here and the Step 5 file view, so
// both render against one stylesheet. The Forge UI is dark, so use a dark
// syntax style (github-dark) — a light style is unreadable on the dark surface.
const chromaStyle = "github-dark"

// markdownEngine is the configured goldmark instance. README content is
// untrusted repository data, so raw HTML is escaped (WithUnsafe is NOT set) and
// the chroma highlighter runs in class mode — it emits <span class="…"> tokens
// styled by the GenerateCSS stylesheet rather than inline colors.
var markdownEngine goldmark.Markdown = goldmark.New(
	goldmark.WithExtensions(
		extension.GFM,
		highlighting.NewHighlighting(
			highlighting.WithStyle(chromaStyle),
			highlighting.WithFormatOptions(
				chromahtml.WithClasses(true),
			),
		),
	),
	goldmark.WithRendererOptions(
		html.WithHardWraps(),
		html.WithXHTML(),
		// WithUnsafe is intentionally omitted: README is repo content, keep raw
		// HTML escaped.
	),
)

// Markdown renders GitHub-flavored markdown source into a templ component. The
// produced HTML is goldmark output (escaped raw HTML, class-mode highlighted
// code blocks) wrapped with templ.Raw — goldmark already sanitizes/escapes, so
// the bytes are safe to emit verbatim.
func Markdown(src []byte) (templ.Component, error) {
	var buf bytes.Buffer
	if err := markdownEngine.Convert(src, &buf); err != nil {
		return nil, err
	}
	return templ.Raw(buf.String()), nil
}
