package spf

import (
	"math"
	"math/rand"
	"time"
)

type retryResolver struct {
	min    time.Duration
	max    time.Duration
	factor float64
	jitter bool
	rr     []Resolver
}

type RetryResolverOption func(r *retryResolver)

func BackoffDelayMin(d time.Duration) RetryResolverOption {
	return func(r *retryResolver) {
		if d <= 0 {
			return
		}
		r.min = d
	}
}

func BackoffFactor(f float64) RetryResolverOption {
	return func(r *retryResolver) {
		if f <= 0 {
			return
		}
		r.factor = f
	}
}

func BackoffJitter(b bool) RetryResolverOption {
	return func(r *retryResolver) {
		r.jitter = b
	}
}

func BackoffTimeout(d time.Duration) RetryResolverOption {
	return func(r *retryResolver) {
		if d <= 0 {
			d = 2 * time.Second
		}
		r.max = d
	}
}

// NewRetryResolver implements round-robin retry with backoff delay
func NewRetryResolver(rr []Resolver, opts ...RetryResolverOption) Resolver {
	resolver := &retryResolver{
		min:    100 * time.Millisecond,
		max:    2 * time.Second,
		factor: 2,
		jitter: true,
		rr:     rr,
	}

	for _, opt := range opts {
		opt(resolver)
	}
	return resolver
}

// LookupTXTStrict returns DNS TXT records for the given name, however it
// will return ErrDNSPermerror upon NXDOMAIN (RCODE 3)
func (r *retryResolver) LookupTXTStrict(name string) ([]string, error) {
	expired := r.expiredFunc()
	for attempt := 0; ; attempt++ {
		for _, next := range r.rr {
			v, err := next.LookupTXTStrict(name)
			if err != ErrDNSTemperror || expired() {
				return v, err
			}
		}
		time.Sleep(r.backoff(attempt))
	}
}

// LookupTXT returns the DNS TXT records for the given domain name.
func (r *retryResolver) LookupTXT(name string) ([]string, error) {
	expired := r.expiredFunc()
	for attempt := 0; ; attempt++ {
		for _, next := range r.rr {
			v, err := next.LookupTXT(name)
			if err != ErrDNSTemperror || expired() {
				return v, err
			}
		}
		time.Sleep(r.backoff(attempt))
	}
}

// Exists is used for a DNS A RR lookup (even when the
// connection type is IPv6).  If any A record is returned, this
// mechanism matches.
func (r *retryResolver) Exists(name string) (bool, error) {
	expired := r.expiredFunc()
	for attempt := 0; ; attempt++ {
		for _, next := range r.rr {
			v, err := next.Exists(name)
			if err != ErrDNSTemperror || expired() {
				return v, err
			}
		}
		time.Sleep(r.backoff(attempt))
	}
}

// MatchIP provides an address lookup, which should be done on the name
// using the type of lookup (A or AAAA).
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
func (r *retryResolver) MatchIP(name string, matcher IPMatcherFunc) (bool, error) {
	expired := r.expiredFunc()
	for attempt := 0; ; attempt++ {
		for _, next := range r.rr {
			v, err := next.MatchIP(name, matcher)
			if err != ErrDNSTemperror || expired() {
				return v, err
			}
		}
		time.Sleep(r.backoff(attempt))
	}
}

// MatchMX is similar to MatchIP but first performs an MX lookup on the
// name.  Then it performs an address lookup on each MX name returned.
// Then IPMatcherFunc used to compare checked IP to the returned address(es).
// If any address matches, the mechanism matches
func (r *retryResolver) MatchMX(name string, matcher IPMatcherFunc) (bool, error) {
	expired := r.expiredFunc()
	for attempt := 0; ; attempt++ {
		for _, next := range r.rr {
			v, err := next.MatchMX(name, matcher)
			if err != ErrDNSTemperror || expired() {
				return v, err
			}
		}
		time.Sleep(r.backoff(attempt))
	}
}

func (r *retryResolver) expiredFunc() func() bool {
	start := time.Now()
	return func() bool {
		return time.Since(start) > r.max
	}
}

// backoff calculates timeout for the next attempt. Attempt should be zero based.
// Adapted from https://github.com/jpillora/backoff/blob/master/backoff.go
func (r *retryResolver) backoff(attempt int) time.Duration {
	if r.min >= r.max {
		// short-circuit
		return r.max
	}
	const maxInt64 = float64(math.MaxInt64 - 512)

	//calculate this duration
	minf := float64(r.min)
	durf := minf * math.Pow(r.factor, float64(attempt))
	if r.jitter {
		durf = rand.Float64()*(durf-minf) + minf
	}
	//ensure float64 wont overflow int64
	if durf > maxInt64 {
		return r.max
	}
	dur := time.Duration(durf)
	//keep within bounds
	if dur < r.min {
		return r.min
	} else if dur > r.max {
		return r.max
	}
	return dur
}
