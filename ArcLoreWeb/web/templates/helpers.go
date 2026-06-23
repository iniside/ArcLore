package templates

import "strings"

// Initials returns up to two uppercase letters for an avatar bubble: first
// letters of the first two words, else the first two characters, else "?".
func Initials(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "?"
	}
	parts := strings.Fields(s)
	if len(parts) >= 2 {
		return strings.ToUpper(parts[0][:1] + parts[1][:1])
	}
	if len(s) >= 2 {
		return strings.ToUpper(s[:2])
	}
	return strings.ToUpper(s[:1])
}
