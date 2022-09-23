package spf

import (
	"errors"
	"testing"
	"time"
)

type brokenResolver struct {
	id  int
	d   time.Duration
	c   int
	e   error
	try *int
}

func (r *brokenResolver) error() error {
	if r.c == 0 {
		return r.e
	}
	time.Sleep(r.d)
	r.c--
	return ErrDNSTemperror
}

func (r *brokenResolver) LookupTXTStrict(name string) ([]string, time.Duration, error) {
	return nil, 0, r.error()
}

func (r *brokenResolver) LookupTXT(name string) ([]string, time.Duration, error) {
	return nil, 0, r.error()
}

func (r *brokenResolver) Exists(name string) (bool, time.Duration, error) {
	return false, 0, r.error()
}

func (r *brokenResolver) MatchIP(name string, matcher IPMatcherFunc) (bool, time.Duration, error) {
	return false, 0, r.error()
}

func (r *brokenResolver) MatchMX(name string, matcher IPMatcherFunc) (bool, time.Duration, error) {
	return false, 0, r.error()
}

func TestRetryResolver_Exists(t *testing.T) {
	lastErr := errors.New("last error")

	var tries int
	tests := []struct {
		name  string
		r     Resolver
		d     time.Duration
		e     error
		tries int
	}{
		{"3 tries in time", NewRetryResolver([]Resolver{
			&brokenResolver{id: 0, c: 1, d: 600 * time.Millisecond, e: lastErr, try: &tries},
			&brokenResolver{id: 1, c: 1, d: 600 * time.Millisecond, e: lastErr, try: &tries},
			&brokenResolver{id: 2, c: 1, d: 600 * time.Millisecond, e: lastErr, try: &tries},
		}), 2 * time.Second, lastErr, 3},
		{"4 tries expired", NewRetryResolver([]Resolver{
			&brokenResolver{id: 0, c: 1, d: 700 * time.Millisecond, e: lastErr, try: &tries},
			&brokenResolver{id: 1, c: 1, d: 700 * time.Millisecond, e: lastErr, try: &tries},
			&brokenResolver{id: 2, c: 1, d: 700 * time.Millisecond, e: lastErr, try: &tries},
		}), 2200 * time.Millisecond, ErrDNSTemperror, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tries = 0
			start := time.Now()
			_, _, err := tt.r.Exists("domain.")
			if err != tt.e {
				t.Errorf("Exists() error = %v, wantErr %v", err, tt.e)
				return
			}
			if d := time.Since(start); d > tt.d {
				t.Errorf("Exists() timeout = %v, want %v", d, tt.d)
			}
			if tries > tt.tries {
				t.Errorf("Exists() tries = %v, want %v", tries, tt.tries)
			}
		})
	}
}
