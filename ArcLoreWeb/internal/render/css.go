package render

import (
	"io"

	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/styles"
)

// GenerateCSS writes the chroma class-mode stylesheet for the shared chroma
// style (chromaStyle) to w. This one stylesheet covers BOTH the markdown code
// fences rendered by Markdown and the Step 5 file view — both highlight in
// class mode against these classes. It is served at /static/chroma.css.
func GenerateCSS(w io.Writer) error {
	formatter := chromahtml.New(chromahtml.WithClasses(true))
	return formatter.WriteCSS(w, styles.Get(chromaStyle))
}
