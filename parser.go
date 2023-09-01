package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
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

// SyntaxError represents parsing error, it holds reference to faulty Token
// as well as error describing fault
type SyntaxError struct {
	token *Token
	err   error
}

func (e SyntaxError) Error() string {
	var (
		p     strings.Builder
		cause = error(e)
	)
	for {
		var (
			t    *Token
			next bool
		)
		t, cause, next = Unwrap(cause)
		if !next {
			break
		}
		if p.Len() > 0 {
			p.WriteByte(' ')
		}
		p.WriteString(t.String())
	}
	m := strings.Builder{}
	m.WriteString(cause.Error())
	if p.Len() > 0 {
		m.WriteByte(' ')
		m.WriteByte('[')
		m.WriteString(p.String())
		m.WriteByte(']')
	}
	return m.String()
}

func Unwrap(e error) (*Token, error, bool) {
	se, ok := e.(SyntaxError)
	if ok {
		return se.token, se.err, true
	}
	return nil, e, false
}

func Cause(e error) (string, error) {
	var t, lastToken *Token
	for next := true; next; t, e, next = Unwrap(e) {
		if t != nil {
			lastToken = t
		}
	}
	return lastToken.String(), e
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
	sender             string
	domain             string
	heloDomain         string
	ip                 net.IP
	query              string
	resolver           Resolver
	listener           Listener
	ignoreMatches      bool
	options            []Option
	visited            *stringsStack
	evaluatedOn        time.Time
	receivingFQDN      string
	stopAtError        func(error) bool
	partialMacros      bool
	fireFirstMatchOnce *sync.Once
}

// newParser creates new Parser objects and returns its reference.
// It accepts CheckHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func newParser(opts ...Option) *parser {
	return newParserWithVisited(newStringsStack(), new(sync.Once), opts...)
}

// newParserWithVisited creates new Parser objects with prepopulated map of visited domains and returns its reference.
// It accepts CheckHost() parameters as well as SPF query (fetched from TXT RR
// during initial DNS lookup.
func newParserWithVisited(visited *stringsStack, fireFirstMatchOnce *sync.Once, opts ...Option) *parser {
	p := &parser{
		// mechanisms: make([]*Token, 0, 10),
		resolver:           NewLimitedResolver(&DNSResolver{}, 10, 10, 2),
		options:            opts,
		visited:            visited,
		receivingFQDN:      "unknown",
		evaluatedOn:        time.Now().UTC(),
		fireFirstMatchOnce: fireFirstMatchOnce,
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
func (p *parser) checkHost(ip net.IP, domain, sender string) (r Result, expl string, spf string, err error) {
	var u unused
	var extras *ResponseExtras
	p.fireCheckHost(ip, domain, sender)
	defer func() {
		p.fireCheckHostResult(r, expl, extras, err)
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
		return None, "", "", newInvalidDomainError(domain)
	}

	if p.visited.has(NormalizeFQDN(domain)) {
		return Permerror, "", "", ErrLoopDetected
	}

	var txts []string
	txts, extras, err = p.resolver.LookupTXTStrict(NormalizeFQDN(domain))
	if extras.Void() {
		p.fireVoidLookup(nil, domain)
	}

	switch err {
	case nil:
		// continue
	case ErrDNSLimitExceeded:
		return Permerror, "", "", err
	case ErrDNSPermerror:
		return None, "", "", err
	default:
		return Temperror, "", "", err
	}

	// If the resultant record set includes no records, check_host()
	// produces the "none" result.  If the resultant record set includes
	// more than one record, check_host() produces the "permerror" result.
	spf, err = filterSPF(txts)
	if err != nil {
		return Permerror, "", "", err
	}
	if spf == "" {
		return None, "", "", ErrSPFNotFound
	}

	r, expl, u, err = newParserWithVisited(p.visited, p.fireFirstMatchOnce, p.options...).with(spf, sender, domain, ip).check()
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
	mechanisms []*Token
	redirect   *Token
}

// check aggregates all steps required for SPF evaluation.
// After lexing and tokenizing step it sorts tokens (and returns Permerror if
// there is any syntax error) and starts evaluating
// each Token (from left to right). Once a Token matches parse stops and
// returns matched result.
func (p *parser) check() (Result, string, unused, error) {
	p.visited.push(p.domain)
	defer p.visited.pop()

	p.fireSPFRecord(p.query)
	tokens := lex(p.query)

	var (
		result  = Neutral
		matches bool
		token   *Token
		i       int
		extras  *ResponseExtras
	)

	mechanisms, redirect, explanation, err := sortTokens(tokens)
	if err != nil {
		return Permerror, "", unused{mechanisms, redirect}, err
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
			matches, result, extras, err = p.parseA(token)
		case tIP4:
			matches, result, err = p.parseIP4(token)
		case tIP6:
			matches, result, err = p.parseIP6(token)
		case tMX:
			matches, result, extras, err = p.parseMX(token)
		case tInclude:
			matches, result, err = p.parseInclude(token)
		case tExists:
			matches, result, extras, err = p.parseExists(token)
		case tPTR:
			matches, result, extras, err = p.parsePtr(token)
		default:
			p.fireDirective(token, "")
		}

		if !p.ignoreMatches && matches {
			var s string
			if result == Fail && explanation != nil {
				s, err = p.handleExplanation(explanation)
			}
			p.fireMatch(token, result, s, extras, err)
			return result, s, unused{mechanisms[i+1:], redirect}, err
		}

		// Store the first match result if not already set
		if p.ignoreMatches && matches {
			p.fireFirstMatch(result, err)
		}

		p.fireNonMatch(token, result, err)

		// in walker-mode we want to count number of errors and check the counter against some threshold
		if p.ignoreMatches && p.stopAtError != nil && p.stopAtError(err) {
			return unreliableResult, "", unused{mechanisms[i+1:], redirect}, ErrTooManyErrors
		}

		// all expected errors should be thrown with matches=true
		// others are being registered by listener
	}

	if !all {
		result, err = p.handleRedirect(redirect)
	}

	if p.ignoreMatches {
		return unreliableResult, "", unused{}, ErrUnreliableResult
	}

	return result, "", unused{}, err
}

func (p *parser) fireCheckHost(ip net.IP, domain, sender string) {
	if p.listener == nil {
		return
	}
	p.listener.CheckHost(ip, domain, sender)
}

func (p *parser) fireCheckHostResult(r Result, explanation string, extras *ResponseExtras, e error) {
	if p.listener == nil {
		return
	}
	p.listener.CheckHostResult(r, explanation, extras, e)
}

func (p *parser) fireSPFRecord(s string) {
	if p.listener == nil {
		return
	}
	p.listener.SPFRecord(s)
}

func (p *parser) fireDirective(t *Token, effectiveValue string) {
	if p.listener == nil {
		return
	}
	p.listener.Directive(false, t.qualifier.String(), t.mechanism.String(), t.value, effectiveValue)
}

func (p *parser) fireMatchingIP(t *Token, fqdn string, ipn net.IPNet, host string, ip net.IP) {
	if p.listener == nil {
		return
	}
	p.listener.MatchingIP(t.qualifier.String(), t.mechanism.String(), t.value, fqdn, ipn, host, ip)
}

func (p *parser) fireUnusedDirective(t *Token) {
	if p.listener == nil || t == nil {
		return
	}
	p.listener.Directive(true, t.qualifier.String(), t.mechanism.String(), t.value, "")
}

func (p *parser) fireNonMatch(t *Token, r Result, e error) {
	if p.listener == nil {
		return
	}
	p.listener.NonMatch(t.qualifier.String(), t.mechanism.String(), t.value, r, e)
}

func (p *parser) fireMatch(t *Token, r Result, explanation string, extras *ResponseExtras, e error) {
	if p.listener == nil {
		return
	}
	p.listener.Match(t.qualifier.String(), t.mechanism.String(), t.value, r, explanation, extras, e)
}

func (p *parser) fireVoidLookup(t *Token, fqdn string) {
	if p.listener == nil {
		return
	}

	if t == nil {
		p.listener.VoidLookup("", "", "", fqdn)
		return
	}

	p.listener.VoidLookup(t.qualifier.String(), t.mechanism.String(), t.value, fqdn)
}

func (p *parser) fireFirstMatch(r Result, e error) {
	if p.listener == nil || p.fireFirstMatchOnce == nil {
		return
	}

	p.fireFirstMatchOnce.Do(func() {
		p.listener.FirstMatch(r, e)
	})
}

func sortTokens(tokens []*Token) (mechanisms []*Token, redirect, explanation *Token, err error) {
	mechanisms = make([]*Token, 0, len(tokens))
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

func (p *parser) parseVersion(t *Token) (bool, Result, error) {
	p.fireDirective(t, "")
	if t.value == "spf1" {
		return false, None, nil
	}
	return true, Permerror, SyntaxError{
		t,
		fmt.Errorf("invalid spf qualifier: %v", t.value),
	}
}

func (p *parser) parseAll(t *Token) (bool, Result, error) {
	p.fireDirective(t, "")
	result, err := matchingResult(t.qualifier)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	return true, result, nil
}

func (p *parser) parseIP4(t *Token) (bool, Result, error) {
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

func (p *parser) parseIP6(t *Token) (bool, Result, error) {
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

func (p *parser) parseA(t *Token) (bool, Result, *ResponseExtras, error) {
	fqdn, ip4Mask, ip6Mask, err := splitDomainDualCIDR(domainSpec(t.value, p.domain))
	if err == nil {
		fqdn, _, err = parseMacro(p, fqdn, false)
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
		return true, Permerror, nil, SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)

	found, extras, err := p.resolver.MatchIP(fqdn, func(ip net.IP, host string) (bool, error) {
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
	if extras.Void() {
		p.fireVoidLookup(t, fqdn)
	}

	return found, result, extras, err
}

func (p *parser) parseMX(t *Token) (bool, Result, *ResponseExtras, error) {
	fqdn, ip4Mask, ip6Mask, err := splitDomainDualCIDR(domainSpec(t.value, p.domain))
	if err == nil {
		fqdn, _, err = parseMacro(p, fqdn, false)
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
		return true, Permerror, nil, SyntaxError{t, err}
	}

	result, _ := matchingResult(t.qualifier)
	found, extras, err := p.resolver.MatchMX(fqdn, func(ip net.IP, host string) (bool, error) {
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
	if extras.Void() {
		p.fireVoidLookup(t, fqdn)
	}
	if err != nil {
		return true, Permerror, nil, SyntaxError{t, err}
	}
	return found, result, extras, err
}

func (p *parser) parseInclude(t *Token) (bool, Result, error) {
	domain, missingMacros, err := parseMacro(p, t.value, false)
	if err == nil {
		domain, err = truncateFQDN(domain)
	}
	if err == nil && !isDomainName(domain) {
		err = newInvalidDomainError(domain)
	}
	if len(missingMacros) > 0 {
		err = newMissingMacrosError(domain, missingMacros)
	}

	domain = NormalizeFQDN(domain)
	p.fireDirective(t, domain)
	if err != nil {
		return true, Permerror, SyntaxError{t, err}
	}
	if domain == "" {
		return true, Permerror, SyntaxError{t, ErrEmptyDomain}
	}
	theirResult, _, _, err := p.checkHost(p.ip, domain, p.sender)
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
	*/if err != nil {
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

func (p *parser) parseExists(t *Token) (bool, Result, *ResponseExtras, error) {
	resolvedDomain, missingMacros, err := parseMacroToken(p, t)
	if err == nil {
		resolvedDomain, err = truncateFQDN(resolvedDomain)
	}
	if err == nil && !isDomainName(resolvedDomain) {
		err = newInvalidDomainError(resolvedDomain)
	}
	if len(missingMacros) > 0 {
		err = newMissingMacrosError(resolvedDomain, missingMacros)
	}

	resolvedDomain = NormalizeFQDN(resolvedDomain)
	p.fireDirective(t, resolvedDomain)
	if err != nil {
		return true, Permerror, nil, SyntaxError{t, err}
	}
	if resolvedDomain == "" {
		return true, Permerror, nil, SyntaxError{t, ErrEmptyDomain}
	}

	result, _ := matchingResult(t.qualifier)

	found, extras, err := p.resolver.Exists(resolvedDomain)
	if extras.Void() {
		p.fireVoidLookup(t, resolvedDomain)
	}

	switch err {
	case nil:
		return found, result, extras, nil
	case ErrDNSPermerror:
		return false, result, nil, nil
	default:
		return false, Temperror, nil, err // was true 8-|
	}
}

// https://www.rfc-editor.org/rfc/rfc7208#section-5.5
func (p *parser) parsePtr(t *Token) (bool, Result, *ResponseExtras, error) {
	fqdn := domainSpec(t.value, p.domain)
	fqdn, _, err := parseMacro(p, fqdn, false)
	if err == nil {
		fqdn, err = truncateFQDN(fqdn)
	}
	if err == nil && !isDomainName(fqdn) {
		err = newInvalidDomainError(fqdn)
	}
	fqdn = NormalizeFQDN(fqdn)
	p.fireDirective(t, fqdn)
	if err != nil {
		return true, Permerror, nil, SyntaxError{t, err}
	}

	ptrs, extras, err := p.resolver.LookupPTR(p.ip.String())
	if extras.Void() {
		p.fireVoidLookup(t, fqdn)
	}

	switch err {
	case nil:
		// continue
	case ErrDNSLimitExceeded:
		return false, Permerror, extras, err
	case ErrDNSPermerror:
		return false, None, extras, err
	default:
		return false, Temperror, extras, err
	}

	result, _ := matchingResult(t.qualifier)

	for _, ptrDomain := range ptrs {
		found, _, err := p.resolver.MatchIP(ptrDomain, func(ip net.IP, host string) (bool, error) {
			if ip.Equal(p.ip) {
				// Check if the PTR domain matches the target name or is a subdomain of the target name
				if strings.HasSuffix(ptrDomain, fqdn) || fqdn == ptrDomain {
					return true, nil // Match found
				}
			}
			return false, nil
		})
		if err != nil {
			continue
		}

		if found {
			return true, result, nil, nil
		}
	}

	return false, Fail, nil, nil
}

func (p *parser) handleRedirect(t *Token) (Result, error) {
	if t == nil {
		return Neutral, nil
	}

	var (
		err    error
		result Result
	)

	domain, _, err := parseMacro(p, t.value, false)
	if err == nil {
		domain, err = truncateFQDN(domain)
	}
	if err == nil && !isDomainName(domain) {
		err = newInvalidDomainError(domain)
	}
	redirectDomain := NormalizeFQDN(domain)

	p.fireDirective(t, redirectDomain)
	if err != nil {
		return Permerror, SyntaxError{t, err}
	}

	if result, _, _, err = p.checkHost(p.ip, redirectDomain, p.sender); err != nil {
		// TODO(zaccone): confirm result value
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

func (p *parser) handleExplanation(t *Token) (string, error) {
	domain, _, err := parseMacroToken(p, t)
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
	if !isDomainName(domain) {
		return "", SyntaxError{t, newInvalidDomainError(domain)}
	}

	txts, _, err := p.resolver.LookupTXT(NormalizeFQDN(domain))
	if err != nil {
		return "", err
	}

	// RFC 7208, section 6.2 specifies that result strings should be
	// concatenated with no spaces.
	// TODO URL escaping MUST be performed for characters
	//  not in the "unreserved" set, which is defined in [RFC3986].
	//  https://tools.ietf.org/html/rfc7208#section-7.3
	//  looks like we need to do it after truncating
	exp, _, err := parseMacro(p, strings.Join(txts, ""), true)
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
