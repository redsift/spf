package spf

import (
	"net"
	"sync/atomic"
)

// LimitedResolver wraps a Resolver and limits number of lookups possible to do
// with it. All overlimited calls return ErrDNSLimitExceeded.
type LimitedResolver struct {
	lookupLimit    int32
	mxQueriesLimit uint16
	resolver       Resolver
}

// NewLimitedResolver returns a resolver which will pass up to lookupLimit calls to r.
// In addition to that limit, the evaluation of each "MX" record will be limited
// to mxQueryLimit.
// All calls over the limit will return ErrDNSLimitExceeded.
// Make sure lookupLimit includes the initial SPF lookup
func NewLimitedResolver(r Resolver, lookupLimit, mxQueriesLimit uint16) Resolver {
	return &LimitedResolver{
		lookupLimit:    int32(lookupLimit), // sure that l is positive or zero
		mxQueriesLimit: mxQueriesLimit,
		resolver:       r,
	}
}

func (r *LimitedResolver) canLookup() bool {
	return atomic.AddInt32(&r.lookupLimit, -1) > 0
}

// LookupTXT returns the DNS TXT records for the given domain name
// and the minimum TTL. Used for "exp" modifier and do not cause DNS query.
func (r *LimitedResolver) LookupTXT(name string) ([]string, *ResponseExtras, error) {
	return r.resolver.LookupTXT(name)
}

// LookupTXTStrict returns the DNS TXT records for the given domain name
// and the minimum TTL. Returns nil and ErrDNSLimitExceeded if total
// number of lookups made by underlying resolver exceed the limit.
// It will also return ErrDNSPermerror upon DNS call return error NXDOMAIN
// (RCODE 3)
func (r *LimitedResolver) LookupTXTStrict(name string) ([]string, *ResponseExtras, error) {
	if !r.canLookup() {
		return nil, nil, ErrDNSLimitExceeded
	}
	return r.resolver.LookupTXTStrict(name)
}

// Exists is used for a DNS A RR lookup (even when the
// connection type is IPv6).  If any A record is returned, this
// mechanism matches and returns the ttl.
// Returns false and ErrDNSLimitExceeded if total number of lookups made
// by underlying resolver exceed the limit.
func (r *LimitedResolver) Exists(name string) (bool, *ResponseExtras, error) {
	if !r.canLookup() {
		return false, nil, ErrDNSLimitExceeded
	}
	return r.resolver.Exists(name)
}

// MatchIP provides an address lookup, which should be done on the name
// using the type of lookup (A or AAAA).
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
// Returns false and ErrDNSLimitExceeded if total number of lookups made
// by underlying resolver exceed the limit. Also return the minimum TTL in true.
func (r *LimitedResolver) MatchIP(name string, matcher IPMatcherFunc) (bool, *ResponseExtras, error) {
	if !r.canLookup() {
		return false, nil, ErrDNSLimitExceeded
	}
	return r.resolver.MatchIP(name, matcher)
}

// MatchMX is similar to MatchIP but first performs an MX lookup on the
// name.  Then it performs an address lookup on each MX name returned.
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches.
//
// In addition to that limit, the evaluation of each "MX" record MUST NOT
// result in querying more than 10 address records -- either "A" or "AAAA"
// resource records.  If this limit is exceeded, the "mx" mechanism MUST
// produce a "permerror" result.
//
// Returns false and ErrDNSLimitExceeded if total number of lookups made
// by underlying resolver exceed the limit. Returns the minimum TTL in true.
func (r *LimitedResolver) MatchMX(name string, matcher IPMatcherFunc) (bool, *ResponseExtras, error) {
	if !r.canLookup() {
		return false, nil, ErrDNSLimitExceeded
	}

	limit := int32(r.mxQueriesLimit)
	return r.resolver.MatchMX(name, func(ip net.IP, name string) (bool, error) {
		if atomic.AddInt32(&limit, -1) < 1 {
			return false, ErrDNSLimitExceeded
		}
		return matcher(ip, name)
	})
}

// LookupPTR returns the DNS PTR records for the given domain name
// and the minimum TTL
func (r *LimitedResolver) LookupPTR(name string) ([]string, *ResponseExtras, error) {
	if !r.canLookup() {
		return nil, nil, ErrDNSLimitExceeded
	}
	return r.resolver.LookupPTR(name)
}
