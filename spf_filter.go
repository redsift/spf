package spf

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsSPFCandidate checks if a string matches the pattern: [WS* v] WS* (=|:) WS* spf (case-insensitive)
// where WS* represents zero or more whitespace characters, and the 'v' part is optional.
func IsSPFCandidate(s string) bool {
	// States in our tokenizer
	const (
		StateV = iota
		StateSep
		StateSPF
	)

	i := 0
	state := StateV

	for i < len(s) {
		// Skip whitespace at the beginning of each iteration
		i = skipWhitespace(s, i)

		// If we don't have enough characters left for a minimum pattern (=spf),
		// bail out early
		if i >= len(s)-3 {
			// We need at least 4 characters left: 1 for separator and 3 for "spf"
			// But we'll allow for the edge case where exactly 4 characters remain
			if i > len(s)-4 {
				return false
			}
		}

		switch state {
		case StateV:
			// We can either match 'v' or directly a separator (= or :)
			r, size := utf8.DecodeRuneInString(s[i:])

			if r == '=' || r == ':' {
				// Directly found a separator
				i += size
				state = StateSPF
			} else if unicode.ToLower(r) == 'v' {
				// Found 'v'
				i += size
				state = StateSep
			} else {
				// Not a 'v' or separator, so consume this character and keep looking
				i += size
				// state remains StateV
			}

		case StateSep:
			// After 'v', look for a separator (= or :)
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == '=' || r == ':' {
				i += size
				state = StateSPF
			} else {
				// Not a separator after 'v', so reset to StateV
				i += size
				state = StateV
			}

		case StateSPF:
			// Check for "spf" (case-insensitive)
			if hasSpfPrefix(s[i:]) {
				// We've successfully matched the pattern
				return true
			} else {
				// Not "spf", so reset to looking from StateV
				_, size := utf8.DecodeRuneInString(s[i:])
				i += size
				state = StateV
			}
		}
	}

	// If we reached the end of the string, we didn't find a complete match
	return false
}

// skipWhitespace advances the index past any whitespace characters
// and returns the new index position.
func skipWhitespace(s string, start int) int {
	i := start
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !unicode.IsSpace(r) {
			break
		}
		i += size
	}
	return i
}

// hasSpfPrefix checks if s starts with "spf" (case-insensitive)
func hasSpfPrefix(s string) bool {
	const target = "spf"

	// Simply check if we have enough bytes
	if len(s) < len(target) {
		return false
	}

	// Compare the first len(target) bytes
	return strings.EqualFold(s[:len(target)], target)
}

// FilterSPFCandidates filters a slice of strings and returns only those
// that match the SPF policy pattern.
func FilterSPFCandidates(lines []string) []string {
	var candidates []string

	for _, line := range lines {
		if IsSPFCandidate(line) {
			candidates = append(candidates, line)
		}
	}

	return candidates
}
