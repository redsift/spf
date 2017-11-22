package spf

import (
	"net"
	"sync"

	"strings"

	"time"

	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

type MiekgDNSResolverOption func(r *miekgDNSResolver)

func MiekgDNSCache(c gcache.Cache) MiekgDNSResolverOption {
	return func(r *miekgDNSResolver) {
		if c == nil {
			return
		}
		r.cache = c
	}
}

// NewMiekgDNSResolver returns new instance of Resolver with default dns.Client
func NewMiekgDNSResolver(addr string, opts ...MiekgDNSResolverOption) (Resolver, error) {
	return NewMiekgDNSResolverWithClient(addr, new(dns.Client), opts...)
}

// NewMiekgDNSResolverWithClient returns new instance of Resolver
func NewMiekgDNSResolverWithClient(addr string, c *dns.Client, opts ...MiekgDNSResolverOption) (Resolver, error) {
	if _, _, e := net.SplitHostPort(addr); e != nil {
		return nil, e
	}
	r := &miekgDNSResolver{
		client:     c,
		serverAddr: addr,
		cache:      nil,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// miekgDNSResolver implements Resolver using github.com/miekg/dns
type miekgDNSResolver struct {
	mu         sync.Mutex
	client     *dns.Client
	cache      gcache.Cache
	serverAddr string
}

func (r *miekgDNSResolver) cachedResponse(req *dns.Msg) (*dns.Msg, bool) {
	if r.cache == nil {
		return nil, false
	}
	res, err := r.cache.Get(req.Question[0]) // dns.Question is comparable https://golang.org/ref/spec#Comparison_operators
	if err != nil {
		return nil, false
	}
	return res.(*dns.Msg), true
}

const maxUint32 = 1<<32 - 1

func (r *miekgDNSResolver) cacheResponse(res *dns.Msg) {
	if r.cache == nil {
		return
	}
	if len(res.Answer) == 0 {
		return
	}
	var ttl uint32 = maxUint32
	for _, a := range res.Answer {
		if d := a.Header().Ttl; d < ttl {
			ttl = d
		}
	}
	if ttl == 0 {
		return
	}
	r.cache.SetWithExpire(res.Question[0], res, time.Duration(ttl)*time.Second)
}

// If the DNS lookup returns a server failure (RCODE 2) or some other
// error (RCODE other than 0 or 3), or if the lookup times out, then
// check_host() terminates immediately with the result "temperror".
// From RFC 7208:
// Several mechanisms rely on information fetched from the DNS.  For
// these DNS queries, except where noted, if the DNS server returns an
// error (RCODE other than 0 or 3) or the query times out, the mechanism
// stops and the topmost check_host() returns "temperror".  If the
// server returns "Name Error" (RCODE 3), then evaluation of the
// mechanism continues as if the server returned no error (RCODE 0) and
// zero answer records.
func (r *miekgDNSResolver) exchange(req *dns.Msg) (*dns.Msg, error) {
	if res, found := r.cachedResponse(req); found {
		return res, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var (
		res *dns.Msg
		err error
	)
	for _, n := range []string{"udp", "tcp"} {
		r.client.Net = n
		res, _, err = r.client.Exchange(req, r.serverAddr)
		if err != dns.ErrTruncated {
			break
		}
	}
	if err != nil {
		return nil, ErrDNSTemperror
	}
	// RCODE 3
	if res.Rcode == dns.RcodeNameError {
		return res, nil
	}
	if res.Rcode != dns.RcodeSuccess {
		return nil, ErrDNSTemperror
	}
	r.cacheResponse(res)
	return res, nil
}

// LookupTXT returns the DNS TXT records for the given domain name.
func (r *miekgDNSResolver) LookupTXT(name string) ([]string, error) {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeTXT)

	res, err := r.exchange(req)
	if err != nil {
		return nil, err
	}

	txts := make([]string, 0, len(res.Answer))
	for _, a := range res.Answer {
		if r, ok := a.(*dns.TXT); ok {
			txts = append(txts, strings.Join(r.Txt, ""))
		}
	}
	return txts, nil
}

// LookupTXTStrict returns DNS TXT records for the given name, however it
// will return ErrDNSPermerror upon NXDOMAIN (RCODE 3)
func (r *miekgDNSResolver) LookupTXTStrict(name string) ([]string, error) {

	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeTXT)

	res, err := r.exchange(req)
	if err != nil {
		return nil, err
	}

	if res.Rcode == dns.RcodeNameError {
		return nil, ErrDNSPermerror
	}

	txts := make([]string, 0, len(res.Answer))
	for _, a := range res.Answer {
		if r, ok := a.(*dns.TXT); ok {
			txts = append(txts, strings.Join(r.Txt, ""))
		}
	}
	return txts, nil
}

// Exists is used for a DNS A RR lookup (even when the
// connection type is IPv6).  If any A record is returned, this
// mechanism matches.
func (r *miekgDNSResolver) Exists(name string) (bool, error) {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)

	res, err := r.exchange(req)
	if err != nil {
		return false, err
	}

	return len(res.Answer) > 0, nil
}

func matchIP(rrs []dns.RR, matcher IPMatcherFunc) (bool, error) {
	for _, rr := range rrs {
		var ip net.IP
		switch a := rr.(type) {
		case *dns.A:
			ip = a.A
		case *dns.AAAA:
			ip = a.AAAA
		}
		if m, e := matcher(ip); m || e != nil {
			return m, e
		}
	}
	return false, nil
}

// MatchIP provides an address lookup, which should be done on the name
// using the type of lookup (A or AAAA).
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
func (r *miekgDNSResolver) MatchIP(name string, matcher IPMatcherFunc) (bool, error) {
	var wg sync.WaitGroup
	qTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	hits := make(chan hit, len(qTypes))

	for _, qType := range qTypes {
		wg.Add(1)
		go func(qType uint16) {
			defer wg.Done()

			req := new(dns.Msg)
			req.SetQuestion(name, qType)
			res, err := r.exchange(req)
			if err != nil {
				hits <- hit{false, err}
				return
			}

			if m, e := matchIP(res.Answer, matcher); m || e != nil {
				hits <- hit{m, e}
				return
			}
		}(qType)
	}

	go func() {
		wg.Wait()
		close(hits)
	}()

	for h := range hits {
		if h.found || h.err != nil {
			return h.found, h.err
		}
	}

	return false, nil
}

// MatchMX is similar to MatchIP but first performs an MX lookup on the
// name.  Then it performs an address lookup on each MX name returned.
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
func (r *miekgDNSResolver) MatchMX(name string, matcher IPMatcherFunc) (bool, error) {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeMX)

	res, err := r.exchange(req)
	if err != nil {
		return false, err
	}

	var wg sync.WaitGroup
	hits := make(chan hit, len(res.Answer))

	for _, rr := range res.Answer {
		mx, ok := rr.(*dns.MX)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(name string) {
			found, err := r.MatchIP(name, matcher)
			hits <- hit{found, err}
			wg.Done()
		}(mx.Mx)
	}

	go func() {
		wg.Wait()
		close(hits)
	}()

	for h := range hits {
		if h.found || h.err != nil {
			return h.found, h.err
		}
	}

	return false, nil
}
