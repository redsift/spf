package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
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
		return internalError, fmt.Errorf("invalid qualifier")
	}
}

// SyntaxError represents parsing error, it holds reference to faulty token
// as well as error describing fault
type SyntaxError struct {
	token *token
	err   error
}

func (e SyntaxError) Error() string {
	return fmt.Sprintf(`error checking '%s': %s`, e.token.String(), e.err.Error())
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
	sender        string
	domain        string
	heloDomain    string
	ip            net.IP
	query         string
	resolver      Resolver
	listener      Listener
	ignoreMatches bool
	options       []Option
	visited       *stringsStack
	evaluatedOn   time.Time
	receivingFQDN string
}

// newParser creates new Parser objects and returns its reference.
// It accepts CheckHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func newParser(opts ...Option) *parser {
	return newParserWithVisited(newStringsStack(), opts...)
}

// newParserWithVisited creates new Parser objects with prepopulated map of visited domains and returns its reference.
// It accepts CheckHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func newParserWithVisited(visited *stringsStack, opts ...Option) *parser {
	p := &parser{
		//mechanisms: make([]*token, 0, 10),
		resolver:      NewLimitedResolver(&DNSResolver{}, 10, 10),
		options:       opts,
		visited:       visited,
		receivingFQDN: "unknown",
		evaluatedOn:   time.Now().UTC(),
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
	var u unused
	p.fireCheckHost(ip, domain, sender)
	defer func() {
		p.fireCheckHostResult(r, expl, err)
		for _, t := range u.mechanisms {
			p.fireUnusedDirective(t)
		}
		p.fireUnusedDirective(u.redirect)
	}()
	/*
	* As per RFC 7208 Section 4.3:
	* If the <domain> is malformed (e.g., label longer than 63
	* characters, zero-length label not at the end, etc.) or is not
	* a multi-label
	* domain name, [...], check_host() immediately returns None
	 */
	if !isDomainName(domain) {
		return None, "", newInvalidDomainError(domain)
	}

	if p.visited.has(domain) {
		return Permerror, "", ErrLoopDetected
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

	r, expl, err, u = newParserWithVisited(p.visited, p.options...).with(spf, sender, domain, ip).check()
	return
}

func (p *parser) with(query, sender, domain string, ip net.IP) *parser {
	p.query = query
	p.sender = sender
	p.domain = domain
	p.ip = ip
	return p
}

type unused struct {
	mechanisms []*token
	redirect   *token
}

// check aggregates all steps required for SPF evaluation.
// After lexing and tokenizing step it sorts tokens (and returns Permerror if
// there is any syntax error) and starts evaluating
// each token (from left to right). Once a token matches parse stops and
// returns matched result.
func (p *parser) check() (Result, string, error, unused) {
	p.visited.push(p.domain)
	defer p.visited.pop()

	p.fireSPFRecord(p.query)
	tokens := lex(p.query)

	var (
		result  = Neutral
		matches bool
		token   *token
		i       int
	)

	mechanisms, redirect, explanation, err := sortTokens(tokens)
	if err != nil {
		return Permerror, "", err, unused{mechanisms, redirect}
	}

	var all bool
	for i, token = range mechanisms {
		switch token.mechanism {
		case tVersion:
			matches, result, err = p.parseVersion(token)
		case tAll:
			all = true
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
		case tPTR:
			_, _, _ = p.parsePtr(token)
		default:
			p.fireDirective(token, "")
		}

		if !p.ignoreMatches && matches {
			var s string
			if result == Fail && explanation != nil {
				s, err = p.handleExplanation(explanation)
			}
			p.fireMatch(token, result, s, err)
			return result, s, err, unused{mechanisms[i+1:], redirect}
		}
		p.fireNonMatch(token, result, err)

		// all expected errors should be thrown with mathes=true
		// others are being registered by listener
	}

	if !all {
		result, err = p.handleRedirect(redirect)
	}

	if p.ignoreMatches {
		return unreliableResult, "", ErrUnreliableResult, unused{}
	}
	return result, "", err, unused{}
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

func (p *parser) fireMatchingIP(t *token, fqdn string, ipn net.IPNet, host string, ip net.IP) {
	if p.listener == nil {
		return
	}
	p.listener.MatchingIP(t.qualifier.String(), t.mechanism.String(), t.value, fqdn, ipn, host, ip)
}

func (p *parser) fireUnusedDirective(t *token) {
	if p.listener == nil || t == nil {
		return
	}
	p.listener.Directive(true, t.qualifier.String(), t.mechanism.String(), t.value, "")
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
	mechanisms = make([]*token, 0, len(tokens))
	for _, token := range tokens {
		if token.isErr() {
			err = SyntaxError{token, ErrSyntaxError}
			return
		}
		if token.mechanism.isMechanism() {
			mechanisms = append(mechanisms, token)
			continue
		}
		if token.mechanism == tRedirect {
			if redirect != nil {
				err = ErrTooManyRedirects
				return
			}
			redirect = token
		}
		if token.mechanism == tExp {
			if explanation != nil {
				err = ErrTooManyExps
				return
			}
			explanation = token
			continue
		}
	}

	return
}

// For several mechanisms, the <domain-spec> is optional.  If it is not
// provided, the <domain> from the check_host() arguments is used.
func domainSpec(s, def string) string {
	if s == "" {
		return def
	}

	if s[0] == '/' { // special case for (mx|a) dual-cidr-length
		return def + s
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
	p.fireDirective(t, t.value)

	result, _ := matchingResult(t.qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.value); err == nil {
		if ip.To4() == nil {
			return true, Permerror, SyntaxError{t, ErrNotIPv4}
		}
		return ipnet.Contains(p.ip), result, nil
	}

	ip := net.ParseIP(t.value).To4()
	if ip == nil {
		return true, Permerror, SyntaxError{t, ErrNotIPv4}
	}
	return ip.Equal(p.ip), result, nil
}

func (p *parser) parseIP6(t *token) (bool, Result, error) {
	p.fireDirective(t, t.value)

	result, _ := matchingResult(t.qualifier)

	if ip, ipnet, err := net.ParseCIDR(t.value); err == nil {
		if ip.To16() == nil {
			return true, Permerror, SyntaxError{t, ErrNotIPv6}
		}
		return ipnet.Contains(p.ip), result, nil
	}

	ip := net.ParseIP(t.value)
	if ip.To4() != nil || ip.To16() == nil {
		return true, Permerror, SyntaxError{t, ErrNotIPv6}
	}
	return ip.Equal(p.ip), result, nil
}

func (p *parser) parseA(t *token) (bool, Result, error) {
	fqdn, ip4Mask, ip6Mask, err := splitDomainDualCIDR(domainSpec(t.value, p.domain))
	if err == nil {
		fqdn, err = parseMacro(p, fqdn, false)
	}
	if err == nil {
		fqdn, err = truncateFQDN(fqdn)
	}
	if err == nil && !isDomainName(fqdn) {
		err = newInvalidDomainError(fqdn)
	}
	fqdn = NormalizeFQDN(fqdn)
	p.fireDirective(t, fqdn)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)

	found, err := p.resolver.MatchIP(fqdn, func(ip net.IP, host string) (bool, error) {
		n := net.IPNet{
			IP: ip,
		}
		switch len(ip) {
		case net.IPv4len:
			n.Mask = ip4Mask
		case net.IPv6len:
			n.Mask = ip6Mask
		}
		p.fireMatchingIP(t, fqdn, n, host, p.ip)
		return n.Contains(p.ip), nil
	})
	return found, result, err
}

func (p *parser) parseMX(t *token) (bool, Result, error) {
	fqdn, ip4Mask, ip6Mask, err := splitDomainDualCIDR(domainSpec(t.value, p.domain))
	if err == nil {
		fqdn, err = parseMacro(p, fqdn, false)
	}
	if err == nil {
		fqdn, err = truncateFQDN(fqdn)
	}
	if err == nil && !isDomainName(fqdn) {
		err = newInvalidDomainError(fqdn)
	}
	fqdn = NormalizeFQDN(fqdn)
	p.fireDirective(t, fqdn)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)
	found, err := p.resolver.MatchMX(fqdn, func(ip net.IP, host string) (bool, error) {
		n := net.IPNet{
			IP: ip,
		}
		switch len(ip) {
		case net.IPv4len:
			n.Mask = ip4Mask
		case net.IPv6len:
			n.Mask = ip6Mask
		}
		p.fireMatchingIP(t, fqdn, n, host, p.ip)
		return n.Contains(p.ip), nil
	})
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	return found, result, err
}

func (p *parser) parseInclude(t *token) (bool, Result, error) {
	domain, err := parseMacro(p, t.value, false)
	if err == nil {
		domain, err = truncateFQDN(domain)
	}
	domain = NormalizeFQDN(domain)
	p.fireDirective(t, domain)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	if domain == "" {
		return true, Permerror, SyntaxError{t, ErrEmptyDomain}
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
	case unreliableResult: // ignoreMatches enabled
		return true, Permerror, ErrUnreliableResult
	default: // this should actually never happen; but better error than panic
		return true, Permerror, fmt.Errorf("internal error: unknown result %s for %s", theirResult, t)
	}

}

func (p *parser) parseExists(t *token) (bool, Result, error) {
	resolvedDomain, err := parseMacroToken(p, t)
	if err == nil {
		resolvedDomain, err = truncateFQDN(resolvedDomain)
	}
	resolvedDomain = NormalizeFQDN(resolvedDomain)
	p.fireDirective(t, resolvedDomain)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	if resolvedDomain == "" {
		return true, Permerror, SyntaxError{t, ErrEmptyDomain}
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

func (p *parser) parsePtr(t *token) (bool, Result, error) {
	p.fireDirective(t, domainSpec(t.value, p.domain))
	return false, internalError, nil
}

func (p *parser) handleRedirect(t *token) (Result, error) {
	if t == nil {
		return Neutral, nil
	}

	var (
		err    error
		result Result
	)

	domain, err := parseMacro(p, t.value, false)
	if err == nil {
		domain, err = truncateFQDN(domain)
	}
	redirectDomain := NormalizeFQDN(domain)

	p.fireDirective(t, redirectDomain)
	if err != nil {
		return Permerror, SyntaxError{t, err}
	}

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
		return "", SyntaxError{t, ErrEmptyDomain}
	}
	domain, err = truncateFQDN(domain)
	if err != nil {
		return "", SyntaxError{t, err}
	}

	txts, err := p.resolver.LookupTXT(NormalizeFQDN(domain))
	if err != nil {
		return "", err
	}

	// RFC 7208, section 6.2 specifies that result strings should be
	// concatenated with no spaces.
	exp, err := parseMacro(p, strings.Join(txts, ""), true)
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
