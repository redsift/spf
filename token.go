package spf

import (
	"fmt"
	"strconv"
	"strings"
)

// UnknownModifierMech constructed so we break policy if someone tries to create a policy out of mechanism string function instead of using actual key
const UnknownModifierMech = ":?"

type tokenType int

const (
	tEOF tokenType = iota
	tErr

	mechanismBeg

	tVersion // used only for v=spf1 starter
	tAll     // all
	tA       // a
	tIP4     // ip4
	tIP6     // ip6
	tMX      // mx
	tPTR     // ptr
	tInclude // include
	tExists  // exists

	mechanismEnd

	modifierBeg

	tRedirect        // redirect
	tExp             // explanation
	tUnknownModifier // unknown modifier

	modifierEnd

	_ // qEmpty - deadcode, not used
	qPlus
	qMinus
	qTilde
	qQuestionMark

	qErr
)

var qualifiers = map[rune]tokenType{
	'+': qPlus,
	'-': qMinus,
	'?': qQuestionMark,
	'~': qTilde,
}

func (tok tokenType) String() string {
	switch tok {
	case tVersion:
		return "v"
	case tAll:
		return "all"
	case tA:
		return "a"
	case tIP4:
		return "ip4"
	case tIP6:
		return "ip6"
	case tMX:
		return "mx"
	case tPTR:
		return "ptr"
	case tInclude:
		return "include"
	case tRedirect:
		return "redirect"
	case tExists:
		return "exists"
	case tExp:
		return "exp"
	case qPlus:
		return "+"
	case qMinus:
		return "-"
	case qQuestionMark:
		return "?"
	case qTilde:
		return "~"
	case tUnknownModifier:
		return UnknownModifierMech
	default:
		return ":" + strconv.Itoa(int(tok))
	}
}

func tokenTypeFromString(s string) tokenType {
	switch strings.ToLower(s) {
	case "v":
		return tVersion
	case "all":
		return tAll
	case "a":
		return tA
	case "ip4":
		return tIP4
	case "ip6":
		return tIP6
	case "mx":
		return tMX
	case "ptr":
		return tPTR
	case "include":
		return tInclude
	case "redirect":
		return tRedirect
	case "exists":
		return tExists
	case "explanation", "exp":
		return tExp
	default:
		return tErr
	}
}

func (tok tokenType) isMechanism() bool {
	return tok > mechanismBeg && tok < mechanismEnd
}

func (tok tokenType) isModifier() bool {
	return tok > modifierBeg && tok < modifierEnd
}

func checkTokenSyntax(tkn *token, delimiter rune) bool {
	if tkn == nil {
		return false
	}

	if tkn.mechanism == tErr && tkn.qualifier == qErr {
		return true // syntax is ok
	}

	// special case for v=spf1 token

	if tkn.mechanism == tVersion {
		return true
	}

	// mechanism include must not have empty content
	if tkn.mechanism == tInclude && tkn.value == "" {
		return false
	}
	if tkn.mechanism.isModifier() && delimiter != '=' {
		return false
	}
	if tkn.mechanism.isMechanism() && delimiter != ':' {
		return false
	}

	return true
}

// token represents SPF term (modifier or mechanism) like all, include, a, mx,
// ptr, ip4, ip6, exists, redirect etc.
// It's a base structure later parsed by Parser.
type token struct {
	mechanism tokenType // all, include, a, mx, ptr, ip4, ip6, exists etc.
	qualifier tokenType // +, -, ~, ?, defaults to +
	key       string    // key for the mechanism
	value     string    // value for the mechanism
}

func (t *token) isErr() bool {
	return t.mechanism == tErr || t.qualifier == qErr
}

func (t *token) String() string {
	if t == nil {
		return ""
	}
	if t.mechanism == tErr || t.qualifier == qErr {
		return fmt.Sprint(t.value)
	}
	q := t.qualifier.String()
	if t.qualifier == qPlus {
		q = ""
	}
	if t.value == "" {
		return fmt.Sprintf("%s%s", q, t.mechanism.String())
	}
	d := ":"
	if t.mechanism == tVersion || t.mechanism > modifierBeg && t.mechanism < modifierEnd {
		d = "="
	}
	if t.value[0] == '/' {
		d = ""
	}
	k := t.mechanism.String()
	if t.mechanism == tUnknownModifier {
		// special case for unknown modifier syntax; we preserve original key
		k = t.key
	}
	return fmt.Sprintf("%s%s%s%s", q, k, d, t.value)
}

func IsKnownMechanism(s string) bool {
	return tokenTypeFromString(s) != tErr
}
