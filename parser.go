package spf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func matchingResult(qualifier tokenType) (Result, error) {
	switch qualifier {
	case qPlus:
		return Pass, nil
	case qMinus:
		return Fail, nil
	case qQuestionMark:
		return Neutral, nil
	case qTilde:
		return Softfail, nil
	default:
		return internalError, fmt.Errorf("invalid qualifier (%d)", qualifier) // should not happen, lexer must reject it before
	}
}

// SyntaxError represents parsing error, it holds reference to faulty token
// as well as error describing fault
type SyntaxError struct {
	token *token
	err   error
}

func (e SyntaxError) Error() string {
	return fmt.Sprintf(`error checking "%s": %s`, e.token.String(), e.err.Error())
}

func (e SyntaxError) Cause() error {
	return e.err
}

func (e SyntaxError) TokenString() string {
	return e.token.String()
}

// parser represents parsing structure. It keeps all arguments provided by top
// level CheckHost method as well as tokenized terms from TXT RR. One should
// call parser.Parse() for a proper SPF evaluation.
type parser struct {
	sender   string
	domain   string
	ip       net.IP
	query    string
	resolver Resolver
	listener Listener
	options  []Option
}

// newParser creates new Parser objects and returns its reference.
// It accepts CheckHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func newParser(opts ...Option) *parser {
	p := &parser{
		//mechanisms: make([]*token, 0, 10),
		resolver: NewLimitedResolver(&DNSResolver{}, 10, 10),
		options:  opts,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// checkHostWithResolver does checking with custom Resolver.
// Note, that DNS lookup limits need to be enforced by provided Resolver.
//
// The function returns result of verification, explanations as result of "exp=",
// and error as the reason for the encountered problem.
func (p *parser) checkHost(ip net.IP, domain, sender string) (r Result, expl string, err error) {
	p.fireCheckHost(ip, domain, sender)
	defer func() { p.fireCheckHostResult(r, expl, err) }()
	/*
	* As per RFC 7208 Section 4.3:
	* If the <domain> is malformed (e.g., label longer than 63
	* characters, zero-length label not at the end, etc.) or is not
	* a multi-label
	* domain name, [...], check_host() immediately returns None
	 */
	if !isDomainName(domain) {
		return None, "", ErrInvalidDomain
	}

	txts, err := p.resolver.LookupTXTStrict(NormalizeFQDN(domain))
	switch err {
	case nil:
		// continue
	case ErrDNSLimitExceeded:
		return Permerror, "", err
	case ErrDNSPermerror:
		return None, "", err
	default:
		return Temperror, "", err
	}

	// If the resultant record set includes no records, check_host()
	// produces the "none" result.  If the resultant record set includes
	// more than one record, check_host() produces the "permerror" result.
	spf, err := filterSPF(txts)
	if err != nil {
		return Permerror, "", err
	}
	if spf == "" {
		return None, "", ErrSPFNotFound
	}

	return newParser(p.options...).with(spf, sender, domain, ip).check()
}

func (p *parser) with(query, sender, domain string, ip net.IP) *parser {
	p.query = query
	p.sender = sender
	p.domain = domain
	p.ip = ip
	return p
}

// check aggregates all steps required for SPF evaluation.
// After lexing and tokenizing step it sorts tokens (and returns Permerror if
// there is any syntax error) and starts evaluating
// each token (from left to right). Once a token matches parse stops and
// returns matched result.
func (p *parser) check() (Result, string, error) {
	p.fireSPFRecord(p.query)
	tokens := lex(p.query)

	mechanisms, redirect, explanation, err := sortTokens(tokens)
	if err != nil {
		return Permerror, "", err
	}

	var result = Neutral
	var matches bool

	for _, token := range mechanisms {
		switch token.mechanism {
		case tVersion:
			matches, result, err = p.parseVersion(token)
		case tAll:
			matches, result, err = p.parseAll(token)
		case tA:
			matches, result, err = p.parseA(token)
		case tIP4:
			matches, result, err = p.parseIP4(token)
		case tIP6:
			matches, result, err = p.parseIP6(token)
		case tMX:
			matches, result, err = p.parseMX(token)
		case tInclude:
			matches, result, err = p.parseInclude(token)
		case tExists:
			matches, result, err = p.parseExists(token)
		default:
			p.fireDirective(token, "")
		}

		if matches {
			var s string
			if result == Fail && explanation != nil {
				s, err = p.handleExplanation(explanation)
			}
			p.fireMatch(token, result, s, err)
			return result, s, err
		}
		p.fireNonMatch(token, result, err)
	}

	result, err = p.handleRedirect(redirect)

	return result, "", err
}

func (p *parser) fireCheckHost(ip net.IP, domain, sender string) {
	if p.listener == nil {
		return
	}
	p.listener.CheckHost(ip, domain, sender)
}

func (p *parser) fireCheckHostResult(r Result, explanation string, e error) {
	if p.listener == nil {
		return
	}
	p.listener.CheckHostResult(r, explanation, e)
}

func (p *parser) fireSPFRecord(s string) {
	if p.listener == nil {
		return
	}
	p.listener.SPFRecord(s)
}
func (p *parser) fireDirective(t *token, effectiveValue string) {
	if p.listener == nil {
		return
	}
	p.listener.Directive(false, t.qualifier.String(), t.mechanism.String(), t.value, effectiveValue)
}

func (p *parser) fireNonMatch(t *token, r Result, e error) {
	if p.listener == nil {
		return
	}
	p.listener.NonMatch(t.qualifier.String(), t.mechanism.String(), t.value, r, e)
}

func (p *parser) fireMatch(t *token, r Result, explanation string, e error) {
	if p.listener == nil {
		return
	}
	p.listener.Match(t.qualifier.String(), t.mechanism.String(), t.value, r, explanation, e)
}

func sortTokens(tokens []*token) (mechanisms []*token, redirect, explanation *token, err error) {
	all := false
	mechanisms = make([]*token, 0, len(tokens))
	for _, token := range tokens {
		if token.mechanism.isErr() {
			err = SyntaxError{token, fmt.Errorf("invalid value: %v", token.value)}
			return
		} else if token.mechanism.isMechanism() && !all {
			mechanisms = append(mechanisms, token)

			if token.mechanism == tAll {
				all = true
			}
		} else {

			if token.mechanism == tRedirect {
				if redirect != nil {
					err = ErrTooManyRedirects
					return
				}
				redirect = token
			} else if token.mechanism == tExp {
				if explanation != nil {
					err = ErrTooManyExps
					return
				}
				explanation = token
			}
		}
	}

	if all {
		redirect = nil
	}

	return
}

func nonemptyString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (p *parser) parseVersion(t *token) (bool, Result, error) {
	p.fireDirective(t, "")
	if t.value == "spf1" {
		return false, None, nil
	}
	return true, Permerror, SyntaxError{t,
		fmt.Errorf("invalid spf qualifier: %v", t.value)}
}

func (p *parser) parseAll(t *token) (bool, Result, error) {
	p.fireDirective(t, "")
	result, err := matchingResult(t.qualifier)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	return true, result, nil

}

func (p *parser) parseIP4(t *token) (bool, Result, error) {
	result, _ := matchingResult(t.qualifier)
	p.fireDirective(t, t.value)

	if ip, ipnet, err := net.ParseCIDR(t.value); err == nil {
		if ip.To4() == nil {
			return true, Permerror, SyntaxError{t, errors.New("address isn't ipv4")}
		}
		return ipnet.Contains(p.ip), result, nil
	}

	ip := net.ParseIP(t.value).To4()
	if ip == nil {
		return true, Permerror, SyntaxError{t, errors.New("address isn't ipv4")}
	}
	return ip.Equal(p.ip), result, nil
}

func (p *parser) parseIP6(t *token) (bool, Result, error) {
	result, _ := matchingResult(t.qualifier)

	p.fireDirective(t, t.value)
	if ip, ipnet, err := net.ParseCIDR(t.value); err == nil {
		if ip.To16() == nil {
			return true, Permerror, SyntaxError{t, errors.New("address isn't ipv6")}
		}
		return ipnet.Contains(p.ip), result, nil

	}

	ip := net.ParseIP(t.value)
	if ip.To4() != nil || ip.To16() == nil {
		return true, Permerror, SyntaxError{t, errors.New("address isn't ipv6")}
	}
	return ip.Equal(p.ip), result, nil

}

func (p *parser) parseA(t *token) (bool, Result, error) {
	host, ip4Mask, ip6Mask, err := splitDomainDualCIDR(nonemptyString(t.value, p.domain))
	host = NormalizeFQDN(host)
	p.fireDirective(t, host)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)

	found, err := p.resolver.MatchIP(host, func(ip net.IP, _ string) (bool, error) {
		n := net.IPNet{
			IP: ip,
		}
		switch len(ip) {
		case net.IPv4len:
			n.Mask = ip4Mask
		case net.IPv6len:
			n.Mask = ip6Mask
		}
		return n.Contains(p.ip), nil
	})
	return found, result, err
}

func (p *parser) parseMX(t *token) (bool, Result, error) {
	host, ip4Mask, ip6Mask, err := splitDomainDualCIDR(nonemptyString(t.value, p.domain))
	host = NormalizeFQDN(host)
	p.fireDirective(t, host)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)
	found, err := p.resolver.MatchMX(host, func(ip net.IP, _ string) (bool, error) {
		n := net.IPNet{
			IP: ip,
		}
		switch len(ip) {
		case net.IPv4len:
			n.Mask = ip4Mask
		case net.IPv6len:
			n.Mask = ip6Mask
		}
		return n.Contains(p.ip), nil
	})
	return found, result, err
}

func (p *parser) parseInclude(t *token) (bool, Result, error) {
	domain := NormalizeFQDN(t.value)
	p.fireDirective(t, domain)
	if domain == "" {
		return true, Permerror, SyntaxError{t, errors.New("empty domain")}
	}
	theirResult, _, err := p.checkHost(p.ip, domain, p.sender)

	/* Adhere to following result table:
	* +---------------------------------+---------------------------------+
	  | A recursive check_host() result | Causes the "include" mechanism  |
	  | of:                             | to:                             |
	  +---------------------------------+---------------------------------+
	  | pass                            | match                           |
	  |                                 |                                 |
	  | fail                            | not match                       |
	  |                                 |                                 |
	  | softfail                        | not match                       |
	  |                                 |                                 |
	  | neutral                         | not match                       |
	  |                                 |                                 |
	  | temperror                       | return temperror                |
	  |                                 |                                 |
	  | permerror                       | return permerror                |
	  |                                 |                                 |
	  | none                            | return permerror                |
	  +---------------------------------+---------------------------------+
	*/

	if err != nil {
		err = SyntaxError{t, err}
	}

	switch theirResult {
	case Pass:
		ourResult, _ := matchingResult(t.qualifier)
		return true, ourResult, err
	case Fail, Softfail, Neutral:
		return false, None, err
	case Temperror:
		return true, Temperror, err
	case None, Permerror:
		return true, Permerror, err
	default: // this should actually never happen
		return true, Permerror, SyntaxError{t, errors.New("unknown result")}
	}

}

func (p *parser) parseExists(t *token) (bool, Result, error) {
	resolvedDomain, err := parseMacroToken(p, t)
	resolvedDomain = NormalizeFQDN(resolvedDomain)
	p.fireDirective(t, resolvedDomain)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	if resolvedDomain == "" {
		return true, Permerror, SyntaxError{t, errors.New("empty domain")}
	}

	result, _ := matchingResult(t.qualifier)

	found, err := p.resolver.Exists(resolvedDomain)
	switch err {
	case nil:
		return found, result, nil
	case ErrDNSPermerror:
		return false, result, nil
	default:
		return false, Temperror, err // was true 8-|
	}
}

func (p *parser) handleRedirect(t *token) (Result, error) {
	if t == nil {
		return Neutral, nil
	}

	var (
		err    error
		result Result
	)

	redirectDomain := NormalizeFQDN(t.value)

	p.fireDirective(t, redirectDomain)

	if result, _, err = p.checkHost(p.ip, redirectDomain, p.sender); err != nil {
		//TODO(zaccone): confirm result value
		result = Permerror
	} else if result == None || result == Permerror {
		// See RFC7208, section 6.1
		//
		// if no SPF record is found, or if the <target-name> is malformed, the
		// result is a "permerror" rather than "none".
		result = Permerror
	}

	return result, err
}

func (p *parser) handleExplanation(t *token) (string, error) {
	domain, err := parseMacroToken(p, t)
	if err != nil {
		return "", SyntaxError{t, err}
	}
	if domain == "" {
		return "", SyntaxError{t, errors.New("empty domain")}
	}

	txts, err := p.resolver.LookupTXT(NormalizeFQDN(domain))
	if err != nil {
		return "", err
	}

	// RFC 7208, section 6.2 specifies that result strings should be
	// concatenated with no spaces.
	exp, err := parseMacro(p, strings.Join(txts, ""))
	if err != nil {
		return "", SyntaxError{t, err}
	}
	return exp, nil
}

func parseCIDRMask(s string, bits int) (net.IPMask, error) {
	if s == "" {
		return net.CIDRMask(bits, bits), nil
	}
	var (
		l   int
		err error
	)
	if l, err = strconv.Atoi(s); err != nil {
		return nil, ErrInvalidCIDRLength
	}
	mask := net.CIDRMask(l, bits)
	if mask == nil {
		return nil, ErrInvalidCIDRLength
	}
	return mask, nil
}

func splitDomainDualCIDR(domain string) (string, net.IPMask, net.IPMask, error) {
	var (
		ip4Mask net.IPMask
		ip6Mask net.IPMask
		ip4Len  string
		ip6Len  string
		err     error
	)

	parts := strings.SplitN(domain, "/", 3)
	domain = parts[0]
	if len(parts) > 1 {
		ip4Len = parts[1]
	}
	if len(parts) > 2 {
		ip6Len = parts[2]
	}

	if !isDomainName(domain) {
		return "", nil, nil, ErrInvalidDomain
	}
	ip4Mask, err = parseCIDRMask(ip4Len, 8*net.IPv4len)
	if err != nil {
		return "", nil, nil, err
	}
	ip6Mask, err = parseCIDRMask(ip6Len, 8*net.IPv6len)
	if err != nil {
		return "", nil, nil, err
	}

	return domain, ip4Mask, ip6Mask, nil
}
