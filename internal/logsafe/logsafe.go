// Package logsafe escapes attacker-influenced text for one-line output.
//
// Paths, comm names and executable names in Phage's verdicts are chosen by
// whoever runs the process. Printed raw, a newline forges an extra journal
// line and an ESC sequence drives the operator's terminal. Clean escapes every
// non-graphic rune (and backslash) Go-style but adds no surrounding quotes, so
// a string that embeds other escaped strings is escaped exactly once — raw
// values are stored (the audit trail is JSON, which escapes on its own) and
// escaped only at the text output.
package logsafe

import "strconv"

// Clean returns s with control characters, invalid UTF-8, backslashes and
// double quotes escaped as in a Go string literal, without the quotes.
func Clean(s string) string {
	q := strconv.QuoteToGraphic(s)
	return q[1 : len(q)-1]
}
