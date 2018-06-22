package spf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// delimiter is a constant rune other than any allowed delimiter.
	// It indicates lack of allowed delimiters, hence no split in delimiter
	delimiter = '*'

	// negative is a special value indicating there will be no split on macro.
	negative = -1
)

type macro struct {
	start  int
	pos    int
	prev   int
	length int
	input  string
	output []string
	state  stateFn
	exp    bool
}

func newMacro(input string, exp bool) *macro {
	return &macro{0, 0, 0, len(input), input, make([]string, 0, 0), nil, exp}
}

type stateFn func(*macro, *parser) (stateFn, error)

// parseMacro evaluates whole input string and replaces keywords with appropriate
// values from
func parseMacro(p *parser, input string, exp bool) (string, error) {
	m := newMacro(input, exp)
	var err error
	for m.state = scanText; m.state != nil; {
		m.state, err = m.state(m, p)
		if err != nil {
			// log error
			return "", err
		}

	}
	return strings.Join(m.output, ""), nil
}

// parseMacroToken evaluates whole input string and replaces keywords with appropriate
// values from
func parseMacroToken(p *parser, t *token) (string, error) {
	return parseMacro(p, t.value, false)
}

// macro.eof() return true when scanned record has ended, false otherwise
func (m *macro) eof() bool { return m.pos >= m.length }

// next() returns next read rune and boolean indicator whether scanned
// record has ended. Method also moves `pos` value to size (length of read rune),
// and `prev` to previous `pos` location.
// Upon eof found, an non nil error is returned.
func (m *macro) next() (rune, error) {
	if m.eof() {
		return 0, fmt.Errorf("unexpected eof for macro (%v)", m.input)
	}
	r, size := utf8.DecodeRuneInString(m.input[m.pos:])
	m.prev = m.pos
	m.pos += size
	return r, nil
}

// macro.moveon() sets macro.start to macro.pos. This is usually done once the
// ident has been scanned.
func (m *macro) moveon() { m.start = m.pos }

// macro.back() moves back current macro.pos to a previous position.
func (m *macro) back() { m.pos = m.prev }

// State functions

func scanText(m *macro, _ *parser) (stateFn, error) {
	for {

		r, err := m.next()

		if err != nil {
			m.output = append(m.output, m.input[m.start:m.pos])
			m.moveon()
			break
		}

		if r == '%' {
			// TODO(zaccone): exercise more with peek(),next(), back()
			m.output = append(m.output, m.input[m.start:m.prev])
			m.moveon()
			return scanPercent, nil
		}

	}
	return nil, nil
}

func scanPercent(m *macro, _ *parser) (stateFn, error) {
	r, err := m.next()
	if err != nil {
		return nil, err
	}
	switch r {
	case '{':
		m.moveon()
		return scanMacro, nil
	case '%':
		m.output = append(m.output, "%")
	case '_':
		m.output = append(m.output, " ")
	case '-':
		m.output = append(m.output, "%20")
	default:
		return nil, fmt.Errorf("forbidden character (%v) after %%", r)
	}

	m.moveon()
	return scanText, nil
}

type item struct {
	value       string
	cardinality int
	delimiter   rune
	reversed    bool
}

func scanMacro(m *macro, p *parser) (stateFn, error) {
	r, err := m.next()
	if err != nil {
		return nil, err
	}
	var curItem item

	//var err error
	var result string
	var email *addrSpec

	errInvalidMacroSyntax := func(e error) (stateFn, error) {
		return nil, fmt.Errorf("wrong macro syntax: %s", e.Error())
	}

	switch r {
	case 's', 'S':
		curItem = item{p.sender, negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'l', 'L':
		email = parseAddrSpec(p.sender, p.sender)
		curItem = item{email.local, negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'o', 'O':
		email = parseAddrSpec(p.sender, p.sender)
		curItem = item{email.domain, negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'h', 'H':
		curItem = item{p.heloDomain, negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'd', 'D':
		curItem = item{p.domain, negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'i', 'I':
		curItem = item{toDottedHex(p.ip), negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'p', 'P':
		// let's not use it for the moment, RFC doesn't recommend it.

	case 'v', 'V':
		// TODO(zaccone): move such functions to some generic utils module
		if p.ip.To4() == nil {
			m.output = append(m.output, "ip6")
		} else {
			m.output = append(m.output, "in-addr")
		}
		m.moveon()

	case 'c', 'C':
		if !m.exp {
			return errInvalidMacroSyntax(errors.New(`'c' macro letter allowed only in "exp" text`))
		}
		curItem = item{p.ip.String(), negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 'r', 'R':
		if !m.exp {
			return errInvalidMacroSyntax(errors.New(`'r' macro letter allowed only in "exp" text`))
		}
		curItem = item{p.receivingFQDN, negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()

	case 't', 'T':
		if !m.exp {
			return errInvalidMacroSyntax(errors.New(`'t' macro letter allowed only in "exp" text`))
		}
		curItem = item{strconv.FormatInt(p.evaluatedOn.UTC().Unix(), 10), negative, delimiter, false}
		m.moveon()
		result, err = parseDelimiter(m, &curItem)
		if err != nil {
			return errInvalidMacroSyntax(err)
		}
		m.output = append(m.output, result)
		m.moveon()
	}

	r, err = m.next()
	if err != nil {
		// macro not ended properly, handle error here
		return nil, err
	} else if r != '}' {
		// macro not ended properly, handle error here
		return nil, fmt.Errorf("unexpected char '%v', expected '}'", r)
	}

	m.moveon()
	return scanText, nil
}

func toDottedHex(ip net.IP) string {
	if len(ip) == net.IPv4len {
		return ip.String()
	}

	const maxLen = len("ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff")
	b := make([]byte, 0, maxLen)

	// Print with possible :: in place of run of zeros
	for i := 0; i < net.IPv6len; i += 1 {
		if i > 0 {
			b = append(b, '.')
		}
		b = appendHex(b, ip[i])
	}
	return string(b)
}

const hexDigit = "0123456789abcdef"

// Convert i to a hexadecimal string. Leading zeros are not printed.
func appendHex(dst []byte, i byte) []byte {
	if i == 0 {
		return append(dst, '0')
	}
	for j := 7; j >= 0; j-- {
		v := i >> uint(j*4)
		if v > 0 {
			dst = append(dst, hexDigit[v&0xf])
		}
	}
	return dst
}

func parseDelimiter(m *macro, curItem *item) (string, error) {
	// ismacroDelimiter is a private function that returns true if the rune is
	// a macro delimiter.
	// It's important to ephasize delimiters defined in RFC 7208 section 7.1,
	// hence separate function for this.
	isMacroDelimiter := func(ch rune) bool {
		return strings.ContainsRune(".-+,/_=", ch)
	}

	var (
		r   rune
		err error
	)
	r, err = m.next()
	if err != nil {
		return "", err
	}

	if isDigit(r) {
		m.back()
		for {
			r, err = m.next()
			if err != nil {
				return "", err
			}

			if !isDigit(r) {
				m.back()
				curItem.cardinality, err = strconv.Atoi(
					m.input[m.start:m.pos])
				if err != nil {
					return "", err
				}
				break
			}
		}

		r, err = m.next()
		if err != nil {
			return "", err
		}
	}

	if r == 'r' || r == 'R' {
		curItem.reversed = true
		r, err = m.next()
		if err != nil {
			return "", err
		}
	}
	if isMacroDelimiter(r) {
		curItem.delimiter = r
		r, err = m.next()
		if err != nil {
			return "", err
		}
	}
	if r != '}' {
		// syntax error
		return "", fmt.Errorf("unexpected char (%v), expected '}'", r)
	}

	m.back()

	// handle curItem
	var parts []string
	if curItem.cardinality > 0 ||
		curItem.reversed ||
		curItem.delimiter != delimiter {

		if curItem.delimiter == delimiter {
			curItem.delimiter = '.'
		}
		parts = strings.Split(curItem.value, string(curItem.delimiter))
		if curItem.reversed {
			first, last := 0, len(parts)-1
			for first < last {
				parts[first], parts[last] = parts[last], parts[first]
				first++
				last--
			}
		}
	} else {
		parts = []string{curItem.value}
	}

	if curItem.cardinality == negative {
		curItem.cardinality = len(parts)
	}

	if curItem.cardinality > negative && curItem.cardinality > len(parts) {
		curItem.cardinality = len(parts)
	}
	return strings.Join(parts[len(parts)-curItem.cardinality:], "."), nil
}
