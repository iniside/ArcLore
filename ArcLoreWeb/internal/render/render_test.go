package render

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestMarkdownRendersHTML checks that Markdown converts markdown to HTML and
// that raw HTML tags in the source are escaped (WithUnsafe is not set).
func TestMarkdownRendersHTML(t *testing.T) {
	cases := []struct {
		name        string
		src         string
		wantContain string
		wantEscaped string
	}{
		{
			name:        "heading",
			src:         "# Hello\n",
			wantContain: "<h1>Hello</h1>",
		},
		{
			name:        "bold",
			src:         "**bold text**\n",
			wantContain: "<strong>bold text</strong>",
		},
		{
			name:        "raw html escaped",
			src:         "<script>alert(1)</script>\n",
			// goldmark without WithUnsafe escapes raw HTML block — the tag must not
			// appear verbatim in the output; it is rendered as an HTML comment or
			// suppressed, so the opening angle bracket itself should not appear as a
			// literal <script> element.
			wantEscaped: "<script>",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			comp, err := Markdown([]byte(tc.src))
			if err != nil {
				t.Fatalf("Markdown: unexpected error: %v", err)
			}
			var buf bytes.Buffer
			if err := comp.Render(context.Background(), &buf); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			got := buf.String()
			if tc.wantContain != "" && !strings.Contains(got, tc.wantContain) {
				t.Errorf("Markdown output missing %q\ngot: %s", tc.wantContain, got)
			}
			if tc.wantEscaped != "" && strings.Contains(got, tc.wantEscaped) {
				t.Errorf("Markdown output should not contain raw %q (HTML must be escaped)\ngot: %s", tc.wantEscaped, got)
			}
		})
	}
}

// TestHighlightProducesHTML checks that Highlight returns a non-empty component
// and that Go source produces different output than plain text (proving lexer
// dispatch works).
func TestHighlightProducesHTML(t *testing.T) {
	goSrc := []byte("package main\n\nfunc main() {}\n")
	plainSrc := []byte("just some text without any code structure here\n")

	goComp, err := Highlight("main.go", goSrc)
	if err != nil {
		t.Fatalf("Highlight(main.go): unexpected error: %v", err)
	}
	var goBuf bytes.Buffer
	if err := goComp.Render(context.Background(), &goBuf); err != nil {
		t.Fatalf("Highlight(main.go).Render: %v", err)
	}
	if goBuf.Len() == 0 {
		t.Fatal("Highlight(main.go): empty output")
	}

	plainComp, err := Highlight("file.txt", plainSrc)
	if err != nil {
		t.Fatalf("Highlight(file.txt): unexpected error: %v", err)
	}
	var plainBuf bytes.Buffer
	if err := plainComp.Render(context.Background(), &plainBuf); err != nil {
		t.Fatalf("Highlight(file.txt).Render: %v", err)
	}
	if plainBuf.Len() == 0 {
		t.Fatal("Highlight(file.txt): empty output")
	}

	if goBuf.String() == plainBuf.String() {
		t.Fatal("Highlight: Go and plain-text outputs are identical — lexer dispatch not working")
	}
}

// TestLexerName checks that the lexer name is non-empty and that a .go file
// resolves to "Go" while an unknown extension falls back to a fallback name.
func TestLexerName(t *testing.T) {
	cases := []struct {
		filename string
		src      []byte
		wantName string
	}{
		{"main.go", []byte("package main"), "Go"},
		{"script.py", []byte("print('hi')"), "Python"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.filename, func(t *testing.T) {
			got := LexerName(tc.filename, tc.src)
			if got == "" {
				t.Fatalf("LexerName(%q): returned empty string", tc.filename)
			}
			if got != tc.wantName {
				t.Errorf("LexerName(%q) = %q, want %q", tc.filename, got, tc.wantName)
			}
		})
	}

	// Unknown extension must still return something non-empty (fallback lexer).
	unknown := LexerName("unknown.xyzzy", []byte("random content"))
	if unknown == "" {
		t.Fatal("LexerName(unknown extension): returned empty string")
	}
}

// TestParseUnifiedDiff checks that a minimal unified diff yields at least one
// parsed file and that empty input yields nil with no error.
func TestParseUnifiedDiff(t *testing.T) {
	t.Run("empty input yields nil", func(t *testing.T) {
		files, err := ParseUnifiedDiff("")
		if err != nil {
			t.Fatalf("ParseUnifiedDiff(empty): unexpected error: %v", err)
		}
		if files != nil {
			t.Fatalf("ParseUnifiedDiff(empty): want nil, got %v", files)
		}
	})

	t.Run("minimal diff yields one file", func(t *testing.T) {
		diff := "diff --git a/foo.txt b/foo.txt\n" +
			"--- a/foo.txt\n" +
			"+++ b/foo.txt\n" +
			"@@ -1 +1 @@\n" +
			"-old line\n" +
			"+new line\n"
		files, err := ParseUnifiedDiff(diff)
		if err != nil {
			t.Fatalf("ParseUnifiedDiff: unexpected error: %v", err)
		}
		if len(files) == 0 {
			t.Fatal("ParseUnifiedDiff: expected at least one file, got none")
		}
	})
}

// TestDiff checks that Diff renders an HTML structure containing expected
// diff-table markup and that content is escaped (no raw < injection).
func TestDiff(t *testing.T) {
	diff := "diff --git a/foo.txt b/foo.txt\n" +
		"--- a/foo.txt\n" +
		"+++ b/foo.txt\n" +
		"@@ -1 +1 @@\n" +
		"-old <script>\n" +
		"+new value\n"

	files, err := ParseUnifiedDiff(diff)
	if err != nil {
		t.Fatalf("ParseUnifiedDiff: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("ParseUnifiedDiff returned no files")
	}

	comp := Diff(files)
	var buf strings.Builder
	if err := comp.Render(context.Background(), &buf); err != nil {
		t.Fatalf("Diff.Render: %v", err)
	}
	got := buf.String()

	if !strings.Contains(got, "diff-table") {
		t.Errorf("Diff output missing diff-table class\ngot: %s", got)
	}
	if !strings.Contains(got, "diff-add") {
		t.Errorf("Diff output missing diff-add row\ngot: %s", got)
	}
	if !strings.Contains(got, "diff-del") {
		t.Errorf("Diff output missing diff-del row\ngot: %s", got)
	}
	// Verify content escaping: the raw <script> literal must not appear verbatim.
	if strings.Contains(got, "<script>") {
		t.Errorf("Diff output contains unescaped <script> — content not escaped\ngot: %s", got)
	}
}

// TestGenerateCSS checks that GenerateCSS writes a non-empty stylesheet to the
// provided writer.
func TestGenerateCSS(t *testing.T) {
	var buf bytes.Buffer
	if err := GenerateCSS(&buf); err != nil {
		t.Fatalf("GenerateCSS: unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("GenerateCSS: wrote empty CSS")
	}
	// The output should look like CSS (contain at least one rule block).
	got := buf.String()
	if !strings.Contains(got, "{") {
		t.Errorf("GenerateCSS: output does not look like CSS (no '{' found)\ngot (first 200 bytes): %.200s", got)
	}
}
