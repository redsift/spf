package spf

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// lexer represents lexing structure
type lexer struct {
	start  int
	pos    int
	prev   int
	length int
	input  string
}

// lex reads SPF record and returns list of Tokens along with
// their modifiers and values. Parser should parse the Tokens and execute
// relevant actions
func lex(input string) []*token {
	var tokens []*token
	l := &lexer{0, 0, 0, len(input), input}
	for {
		token := l.scan()
		if token.mechanism == tEOF {
			break
		}
		tokens = append(tokens, token)
	}
	return tokens
}

// scan scans input and returns a token structure
func (l *lexer) scan() *token {
	for {
		r, eof := l.next()
		if eof {
			return &token{mechanism: tEOF, qualifier: tEOF}
		} else if isWhitespace(r) || l.eof() { // we just scanned some meaningful data
			token := l.scanIdent()
			l.scanWhitespaces()
			l.moveon()
			return token
		}
	}
}

// Lexer.eof() return true when scanned record has ended, false otherwise
func (l *lexer) eof() bool { return l.pos >= l.length }

// Lexer.next() returns next read rune and boolean indicator whether scanned
// record has ended. Method also moves `pos` value to size (length of read rune),
// and `prev` to previous `pos` location.
func (l *lexer) next() (rune, bool) {
	if l.eof() {
		return 0, true
	}
	r, size := utf8.DecodeRuneInString(l.input[l.pos:])
	// TODO(zaccone): check for operation success/failure
	l.prev = l.pos
	l.pos += size
	return r, false
}

// Lexer.moveon() sets Lexer.start to Lexer.pos. This is usually done once the
// ident has been scanned.
func (l *lexer) moveon() { l.start = l.pos }

// Lexer.back() moves back current Lexer.pos to a previous position.
func (l *lexer) back() { l.pos = l.prev }

// scanWhitespaces moves position to a first rune which is not a
// whitespace or tab
func (l *lexer) scanWhitespaces() {
	for {
		if ch, eof := l.next(); eof {
			return
		} else if !isWhitespace(ch) {
			l.back()
			return
		}
	}
}

// scanIdent is a Lexer method executed after an ident was found.
// It operates on a slice with constraints [l.start:l.pos).
// A cursor tries to find delimiters and set proper `mechanism`, `qualifier`
// and value itself.
// The default token has `mechanism` set to tErr, that is, error state.
func (l *lexer) scanIdent() *token {
	t := &token{mechanism: tErr, qualifier: qPlus}
	start := l.start
	cursor := l.start
	hasQualifier := false
loop:
	for cursor < l.pos {
		ch, size := utf8.DecodeRuneInString(l.input[cursor:])
		cursor += size

		switch ch {
		case '+', '-', '~', '?':
			if hasQualifier {
				t.qualifier = qErr // multiple qualifiers
			} else {
				t.qualifier = qualifiers[ch]
				hasQualifier = true
			}
			l.start = cursor
			continue
		case '=', ':', '/':
			if t.qualifier != qErr {
				t.mechanism = tokenTypeFromString(l.input[l.start : cursor-size])
				//t.key = l.input[l.start : cursor-size]
				p := cursor
				if ch == '/' { // special case for (mx|a) dual-cidr-length
					p = cursor - size
					ch = ':' // replace ch with expected delimiter for checkTokenSyntax
				}
				t.value = strings.TrimSpace(l.input[p:l.pos])
			}
			// save qualifier
			q := t.qualifier
			if t.value == "" || !checkTokenSyntax(t, ch) {
				t.qualifier = qErr
				t.mechanism = tErr
			}
			// save mechanism key for future reference
			t.key = l.input[l.start : cursor-size]

			// special case for unknown modifier syntax
			if ch == '=' && t.mechanism == tErr && q != qErr && checkUnknownModifierSyntax(t.key, t.value) {
				t.mechanism = tUnknownModifier
				t.qualifier = q
			}
			break loop
		}
	}

	if t.isErr() {
		t.mechanism = tokenTypeFromString(strings.TrimSpace(l.input[l.start:cursor]))
		if t.isErr() {
			t.mechanism = tErr
			t.qualifier = qErr
			t.value = strings.TrimSpace(l.input[start:l.pos])
		}
	}

	return t
}

var (
	// Define a regular expression that matches the ABNF rule for 'name'
	// name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
	// ALPHA = <A-Z / a-z>
	// DIGIT = <0-9>
	reNameRFC7208 = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-_.]*$`)
	// macro-string     = *( macro-expand / macro-literal )
	// macro-expand     = ( "%{" macro-letter transformers *delimiter "}" ) / "%%" / "%_" / "%-"
	// macro-literal    = %x21-24 / %x26-7E ; visible characters except "%"
	// macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" / "c" / "r" / "t" / "v"
	// transformers     = *DIGIT [ "r" ]
	// delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
	// Notice the addition of \ before the closing } in the macro-expand part.
	// This should force the regex to respect the ABNF rules more closely.
	reMacroStringRFC7208 = regexp.MustCompile(`^((%\{[slodiphcrtv][0-9]*r?[.\-+,/_=]*\})|%%|%_|%-|[\x21\x22\x23\x24\x26-\x7E])*$`)
)

func checkUnknownModifierSyntax(key, value string) bool {
	return reNameRFC7208.MatchString(key) && reMacroStringRFC7208.MatchString(value)
}

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool { return ch == ' ' || ch == '\t' || ch == '\n' }

// isDigit returns true if rune is a numer (between '0' and '9'), false otherwise
func isDigit(ch rune) bool { return ch >= '0' && ch <= '9' }
