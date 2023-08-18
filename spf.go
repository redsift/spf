package spf

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Errors could be used for root couse analysis
var (
	ErrDNSTemperror               = errors.New("temporary DNS error")
	ErrDNSPermerror               = errors.New("permanent DNS error")
	ErrDNSLimitExceeded           = errors.New("limit exceeded")
	ErrDNSVoidLookupLimitExceeded = errors.New("void lookup limit exceeded")
	ErrSPFNotFound                = errors.New("SPF record not found")
	ErrInvalidCIDRLength          = errors.New("invalid CIDR length")
	ErrTooManySPFRecords          = errors.New("too many SPF records")
	ErrTooManyRedirects           = errors.New(`too many "redirect"`)
	ErrTooManyExps                = errors.New(`too many "exp"`)
	ErrSyntaxError                = errors.New(`wrong syntax`)
	ErrEmptyDomain                = errors.New("empty domain")
	ErrNotIPv4                    = errors.New("address isn't ipv4")
	ErrNotIPv6                    = errors.New("address isn't ipv6")
	ErrLoopDetected               = errors.New("infinite recursion detected")
	ErrUnreliableResult           = errors.New("result is unreliable with IgnoreMatches option enabled")
	ErrTooManyErrors              = errors.New("too many errors")
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

func newMissingMacrosError(domain string, macros []string) error {
	return &DomainError{
		Err:    fmt.Sprintf("macros values missing: %s. ", strings.Join(macros, ", ")),
		Domain: domain,
	}
}

// IPMatcherFunc returns true if ip matches to implemented rules.
// If IPMatcherFunc returns any non nil error, the Resolver must stop
// any further processing and use the error as resulting error.
// name is given for information purpose only and
// could be totally ignored by implementation.
type IPMatcherFunc func(ip net.IP, name string) (bool, error)

// ResponseExtras contains additional information returned alongside DNS query results.
type ResponseExtras struct {
	TTL  time.Duration // Minimum TTL of the DNS response
	Void bool          // Indicates if the response is a result of a DNS void lookup.

	// A DNS void lookup, as defined in Section 4.6.4 of RFC 7208 (https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4),
	// is a query for a domain that is intentionally configured to have no associated DNS records,
	// such as an explicit configuration for a "blackhole" or an intentionally nonexistent domain.
	// This type of query typically returns a response with no relevant DNS records (e.g., NXDOMAIN),
	// and the 'Void' field in this struct is set to 'true' to indicate that the response resulted from such a lookup.
}

// Resolver provides an abstraction for DNS layer operations.
type Resolver interface {
	// LookupTXT returns the DNS TXT records for the given domain name,
	// along with additional response information in ResponseExtras.
	LookupTXT(string) ([]string, *ResponseExtras, error)

	// LookupTXTStrict returns DNS TXT records for the given domain name,
	// and returns ErrDNSPermerror upon returned NXDOMAIN (RCODE 3),
	// along with additional response information in ResponseExtras.
	LookupTXTStrict(string) ([]string, *ResponseExtras, error)

	// Exists is used for a DNS A RR lookup (even when the connection type is IPv6).
	// If any A record is returned, this mechanism matches and a bool,
	// along with additional response information in ResponseExtras.
	Exists(string) (bool, *ResponseExtras, error)

	// MatchIP provides an address lookup, which should be done on the name
	// using the type of lookup (A or AAAA). Then IPMatcherFunc is used to compare
	// the checked IP to the returned address(es). If any address matches,
	// the mechanism matches and returns the TTL,
	// along with additional response information in ResponseExtras.
	MatchIP(string, IPMatcherFunc) (bool, *ResponseExtras, error)

	// MatchMX is similar to MatchIP but first performs an MX lookup on the name.
	// Then it performs an address lookup on each MX name returned.
	// IPMatcherFunc is used to compare the checked IP to the returned address(es).
	// If any address matches, the mechanism matches and returns a bool,
	// along with additional response information in ResponseExtras.
	MatchMX(string, IPMatcherFunc) (bool, *ResponseExtras, error)

	// LookupPTR returns the DNS PTR records for the given address,
	// along with additional response information in ResponseExtras.
	LookupPTR(string) ([]string, *ResponseExtras, error)
}

// Option sets an optional parameter for the evaluating e-mail with regard to SPF
type Option func(*parser)

// PartialMacros triggers partial macro expansion. Currently it expands only %{d} with provided domain, if not empty.
// Otherwise it keeps macro body. Escaped symbols like '%%,%-,%_' are not expanded.
func PartialMacros(v bool) Option {
	return func(p *parser) {
		p.partialMacros = v
	}
}

func IgnoreMatches() Option {
	return func(p *parser) {
		p.ignoreMatches = true
	}
}

func ErrorsThreshold(n int) Option {
	check := func(n int) bool { return !(n > 0) }
	stopAtError := func(err error) bool {
		if err == nil {
			return check(n)
		}
		_, cause := Cause(err)
		if cause == ErrTooManyErrors {
			return true
		}
		if cause == ErrUnreliableResult {
			return check(n)
		}
		n--
		return check(n)
	}
	return func(p *parser) {
		if p.stopAtError == nil {
			p.stopAtError = stopAtError
		}
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

func HeloDomain(s string) Option {
	return func(p *parser) {
		if isDomainName(s) {
			p.heloDomain = s
		}
	}
}

func ReceivingFQDN(s string) Option {
	return func(p *parser) {
		if isDomainName(s) {
			p.receivingFQDN = s
		}
	}
}

func EvaluatedOn(t time.Time) Option {
	return func(p *parser) {
		p.evaluatedOn = t
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

	// unreliableResult replaces any other results when IgnoreMatches option enabled
	unreliableResult

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

func (r Result) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

func (r *Result) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*r = 0
		return nil
	}
	switch s := string(text); s {
	case "none":
		*r = None
		return nil
	case "neutral":
		*r = Neutral
		return nil
	case "pass":
		*r = Pass
		return nil
	case "fail":
		*r = Fail
		return nil
	case "softfail":
		*r = Softfail
		return nil
	case "temperror":
		*r = Temperror
		return nil
	case "permerror":
		*r = Permerror
		return nil
	default:
		i, err := strconv.Atoi(s)
		*r = Result(i)
		return err
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
// CheckHost returns result of verification, explanations as result of "exp=", raw discovered SPF policy
// and error as the reason for the encountered problem.
func CheckHost(ip net.IP, domain, sender string, opts ...Option) (Result, string, string, error) {
	return newParser(opts...).checkHost(ip, NormalizeFQDN(domain), sender)
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

// isDomainName checks if a string is a presentation-format domain name
// (currently restricted to hostname-compatible "preferred name" LDH labels and
// SRV-like "underscore labels"; see golang.org/issue/12421).
//
// Copied from https://github.com/golang/go/blob/8a16c71067ca2cfd09281a82ee150a408095f0bc/src/net/dnsclient.go#L60
func isDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
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

// When the result of macro expansion is used in a domain name query, if
// the expanded domain name exceeds 253 characters (the maximum length
// of a domain name in this format), the left side is truncated to fit,
// by removing successive domain labels (and their following dots) until
// the total length does not exceed 253 characters.
func truncateFQDN(s string) (string, error) {
	l := len(s)
	if l < 254 || l == 254 && s[l-1] == '.' {
		if l == 1 {
			return s, nil
		}
		for i := 1; i < l; i++ {
			if s[i-1] == '.' && s[i] == '.' {
				return "", newInvalidDomainError(s)
			}
		}
		return s, nil
	}
	dot := -1
	l = 0
	i := len(s) - 1
	labelLen := 0
	for i >= 0 && l < 253 {
		if s[i] == '.' {
			if labelLen == 0 {
				return "", newInvalidDomainError(s)
			}
			dot = i
			labelLen = 0
		} else {
			labelLen++
		}
		l++
		i--
	}
	if dot < 0 {
		return "", newInvalidDomainError(s)
	}
	if s[i] == '.' {
		return s[i+1:], nil
	}
	return s[dot+1:], nil
}
