package spf

import (
	"strings"
	"unicode/utf8"
)

// IsSPFCandidate checks if a string matches the pattern: [WS* v] WS* (=|:) WS* spf (case-insensitive)
// where WS* represents zero or more whitespace characters, and the 'v' part is optional.
func IsSPFCandidate(s string) bool {
	// States in our tokenizer
	const (
		StateInit = iota // Initial scanning state
		StateV           // After whitespace
		StateSep         // After 'v'
		StateSPF         // After separator
	)

	i := 0
	state := StateInit
	minRequired := 4 // Need at least 4 characters: separator + "spf"

	if len(s) < minRequired {
		return false
	}

	length := len(s) - minRequired
	for i <= length {
		switch state {
		case StateInit:
			// Fast-forward to the next interesting character
			next := strings.IndexAny(s[i:], "=:vV \t")
			if next == -1 {
				// No interesting characters found
				return false
			}

			// Move to the position of the interesting character
			i += next
			r, size := utf8.DecodeRuneInString(s[i:])

			if r == ' ' || r == '\t' {
				state = StateV
			} else if r == '=' || r == ':' {
				state = StateSPF
			} else if r == 'v' || r == 'V' {
				state = StateSep
			}
			i += size

		case StateV:
			i = skipWhitespace(s, i, length)
			if i < 0 {
				return false
			}

			r, size := utf8.DecodeRuneInString(s[i:])
			if r == '=' || r == ':' {
				i += size
				state = StateSPF
			} else if r == 'v' || r == 'V' {
				i += size
				state = StateSep
			} else {
				// Not matching, return to scanning
				i += size
				state = StateInit
			}

		case StateSep:
			i = skipWhitespace(s, i, length)
			if i < 0 {
				return false
			}

			r, size := utf8.DecodeRuneInString(s[i:])
			if r == '=' || r == ':' {
				i += size
				state = StateSPF
			} else {
				// Not a separator after 'v'
				i += size
				state = StateInit
			}

		case StateSPF:
			i = skipWhitespace(s, i, length)
			if i < 0 {
				return false
			}

			if hasPrefixFold(s[i:], "spf") {
				return true
			}
			// Not "spf", back to scanning
			_, size := utf8.DecodeRuneInString(s[i:])
			i += size
			state = StateInit
		}
	}

	return false
}

// skipWhitespace advances the index past any whitespace characters
// and returns the new index position. If the index exceeds maxIdx,
// returns -1 to signal that there's not enough space left to match.
func skipWhitespace(s string, start, maxIdx int) int {
	i := start
	maxIdx = min(maxIdx, len(s))
	for i < maxIdx && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i > maxIdx {
		return -1
	}
	return i
}

// hasPrefixFold checks if s starts with "spf" (case-insensitive)
func hasPrefixFold(s string, prefix string) bool {
	// Simply check if we have enough bytes
	if len(s) < len(prefix) {
		return false
	}

	// Compare the first len(prefix) bytes
	return strings.EqualFold(s[:len(prefix)], prefix)
}

// HasSPFPrefix checks if a given string represents a valid SPF record according to RFC 7208.
//
// The function verifies that:
// 1. The string begins with exactly "v=spf1" (the SPF version identifier)
// 2. The version identifier is either the entire string or is followed by whitespace
//
// Parameters:
//   - s: The string to check, typically a DNS TXT record content
//
// Returns:
//   - bool: true if the string is a valid SPF record, false otherwise
//
// Examples:
//   - "v=spf1 include:_spf.example.com ~all" -> true (valid SPF record)
//   - "v=spf1" -> true (minimal valid SPF record)
//   - "v=spf10 include:example.com" -> false (incorrect version)
//   - "txt=something" -> false (not an SPF record)
//   - "v=spf1something" -> false (no space after version)
func HasSPFPrefix(s string) bool {
	const (
		v    = "v=spf1"
		vLen = 6
	)

	if len(s) < vLen {
		return false
	}
	if len(s) == vLen {
		return s == v
	}
	if s[vLen] != ' ' && s[vLen] != '\t' {
		return false
	}
	return strings.HasPrefix(s, v)
}

// FilterSPFCandidates filters a slice of strings and returns two separate slices:
// 1. candidates - strings that match the SPF pattern but aren't confirmed valid SPF records
// 2. policies - strings that are confirmed valid SPF records per RFC 7208
//
// The function first checks if each line is an SPF candidate using IsSPFCandidate.
// Then it further categorizes the matches:
//   - If the line is a valid SPF record (starts with "v=spf1" followed by space or EOL),
//     it's added to the policies slice.
//   - Otherwise, it's added to the candidates slice, which contains potential SPF records
//     that don't strictly follow the RFC format.
//
// Parameters:
//   - lines: A slice of strings to filter, typically DNS TXT records
//
// Returns:
//   - candidates: Strings that match SPF pattern but aren't strictly valid per RFC 7208
//   - policies: Strings that are valid SPF records per RFC 7208
func FilterSPFCandidates(lines []string) (candidates, policies []string) {
	for _, line := range lines {
		if !IsSPFCandidate(line) {
			continue
		}
		if HasSPFPrefix(line) {
			policies = append(policies, line)
		} else {
			candidates = append(candidates, line)
		}
	}

	return
}
