package spf

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// Errors could be used for root couse analysis
var (
	ErrDNSTemperror      = errors.New("temporary DNS error")
	ErrDNSPermerror      = errors.New("permanent DNS error")
	ErrDNSLimitExceeded  = errors.New("limit exceeded")
	ErrSPFNotFound       = errors.New("SPF record not found")
	ErrInvalidCIDRLength = errors.New("invalid CIDR length")
	ErrTooManySPFRecords = errors.New("too many SPF records")
	ErrTooManyRedirects  = errors.New(`too many "redirect"`)
	ErrTooManyExps       = errors.New(`too many "exp"`)
	ErrSyntaxError       = errors.New(`wrong syntax`)
	ErrEmptyDomain       = errors.New("empty domain")
	ErrNotIPv4           = errors.New("address isn't ipv4")
	ErrNotIPv6           = errors.New("address isn't ipv6")
)

// DomainError represents a domain check error
type DomainError struct {
	Err    string // description of the error
	Domain string // domain checked
}

func (e *DomainError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Domain == "" {
		return e.Err
	}
	return e.Err + ": " + e.Domain
}

func newInvalidDomainError(domain string) error {
	return &DomainError{
		Err:    "invalid domain name",
		Domain: domain,
	}
}

// IPMatcherFunc returns true if ip matches to implemented rules.
// If IPMatcherFunc returns any non nil error, the Resolver must stop
// any further processing and use the error as resulting error.
// name is given for information purpose only and
// could be totally ignored by implementation.
type IPMatcherFunc func(ip net.IP, name string) (bool, error)

// Resolver provides abstraction for DNS layer
type Resolver interface {
	// LookupTXT returns the DNS TXT records for the given domain name.
	LookupTXT(string) ([]string, error)
	// LookupTXTStrict returns DNS TXT records for the given name, however it
	// will return ErrDNSPermerror upon returned NXDOMAIN (RCODE 3)
	LookupTXTStrict(string) ([]string, error)
	// Exists is used for a DNS A RR lookup (even when the
	// connection type is IPv6).  If any A record is returned, this
	// mechanism matches.
	Exists(string) (bool, error)
	// MatchIP provides an address lookup, which should be done on the name
	// using the type of lookup (A or AAAA).
	// Then IPMatcherFunc used to compare checked IP to the returned address(es).
	// If any address matches, the mechanism matches
	MatchIP(string, IPMatcherFunc) (bool, error)
	// MatchMX is similar to MatchIP but first performs an MX lookup on the
	// name.  Then it performs an address lookup on each MX name returned.
	// Then IPMatcherFunc used to compare checked IP to the returned address(es).
	// If any address matches, the mechanism matches
	MatchMX(string, IPMatcherFunc) (bool, error)
}

// Option sets an optional parameter for the evaluating e-mail with regard to SPF
type Option func(*parser)

func IgnoreMatches() Option {
	return func(p *parser) {
		p.ignoreMatches = true
	}
}

func WithResolver(r Resolver) Option {
	return func(p *parser) {
		p.resolver = r
	}
}

func WithListener(l Listener) Option {
	return func(p *parser) {
		p.listener = l
	}
}

// Result represents result of SPF evaluation as it defined by RFC7208
// https://tools.ietf.org/html/rfc7208#section-2.6
type Result int

const (
	_ Result = iota

	// None means either (a) no syntactically valid DNS
	// domain name was extracted from the SMTP session that could be used
	// as the one to be authorized, or (b) no SPF records were retrieved
	// from the DNS.
	None
	// Neutral result means the ADMD has explicitly stated that it
	// is not asserting whether the IP address is authorized.
	Neutral
	// Pass result is an explicit statement that the client
	// is authorized to inject mail with the given identity.
	Pass
	// Fail result is an explicit statement that the client
	// is not authorized to use the domain in the given identity.
	Fail
	// Softfail result is a weak statement by the publishing ADMD
	// that the host is probably not authorized.  It has not published
	// a stronger, more definitive policy that results in a "fail".
	Softfail
	// Temperror result means the SPF verifier encountered a transient
	// (generally DNS) error while performing the check.
	// A later retry may succeed without further DNS operator action.
	Temperror
	// Permerror result means the domain's published records could
	// not be correctly interpreted.
	// This signals an error condition that definitely requires
	// DNS operator intervention to be resolved.
	Permerror

	internalError
)

// String returns string form of the result as defined by RFC7208
// https://tools.ietf.org/html/rfc7208#section-2.6
func (r Result) String() string {
	switch r {
	case None:
		return "none"
	case Neutral:
		return "neutral"
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	case Softfail:
		return "softfail"
	case Temperror:
		return "temperror"
	case Permerror:
		return "permerror"
	default:
		return strconv.Itoa(int(r))
	}
}

// CheckHost is a main entrypoint function evaluating e-mail with regard to
// SPF and it utilizes DNSResolver as a resolver.
// As per RFC 7208 it will accept 3 parameters:
// <ip> - IP{4,6} address of the connected client
// <domain> - domain portion of the MAIL FROM or HELO identity
// <sender> - MAIL FROM or HELO identity
// All the parameters should be parsed and dereferenced from real email fields.
// This means domain should already be extracted from MAIL FROM field so this
// function can focus on the core part.
//
// CheckHost returns result of verification, explanations as result of "exp=",
// and error as the reason for the encountered problem.
func CheckHost(ip net.IP, domain, sender string, opts ...Option) (Result, string, error) {
	return newParser(opts...).checkHost(ip, domain, sender)
}

// Starting with the set of records that were returned by the lookup,
// discard records that do not begin with a version section of exactly
// "v=spf1".  Note that the version section is terminated by either an
// SP character or the end of the record.  As an example, a record with
// a version section of "v=spf10" does not match and is discarded.
func filterSPF(txt []string) (string, error) {
	const (
		v    = "v=spf1"
		vLen = 6
	)
	var (
		spf string
		n   int
	)

	for _, s := range txt {
		if len(s) < vLen {
			continue
		}
		if len(s) == vLen {
			if s == v {
				spf = s
				n++
			}
			continue
		}
		if s[vLen] != ' ' && s[vLen] != '\t' {
			continue
		}
		if !strings.HasPrefix(s, v) {
			continue
		}
		spf = s
		n++
	}
	if n > 1 {
		return "", ErrTooManySPFRecords
	}
	return spf, nil
}

// isDomainName is a 1:1 copy of implementation from
// original golang codebase:
// https://github.com/golang/go/blob/master/src/net/dnsclient.go#L116
// It validates s string for conditions specified in RFC 1035 and RFC 3696
func isDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}

	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return ok
}

// NormalizeFQDN appends a root domain (a dot) to the FQDN.
func NormalizeFQDN(name string) string {
	if len(name) == 0 {
		return ""
	}
	if name[len(name)-1] != '.' {
		name = name + "."
	}
	return strings.ToLower(name)
}
