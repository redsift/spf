package spf

import (
	"net"
	"testing"

	. "github.com/redsift/spf/v2/testing"

	"github.com/miekg/dns"
)

func TestLimitedResolver(t *testing.T) {
	dns.HandleFunc("domain.", Zone(map[uint16][]string{
		dns.TypeMX: {
			"domain. 0 in MX 5 domain.",
		},
		dns.TypeA: {
			"domain. 0 IN A 10.0.0.1",
		},
		dns.TypeTXT: {
			`domain. 0 IN TXT "ok"`,
		},
	}))
	defer dns.HandleRemove("domain.")

	dns.HandleFunc("mxmustfail.", Zone(map[uint16][]string{
		dns.TypeMX: {
			"mxmustfail. 0 in MX 5 mxmustfail.",
		},
		dns.TypeA: {
			"mxmustfail. 0 IN A 10.0.0.1",
			"mxmustfail. 0 IN A 10.0.0.2",
			"mxmustfail. 0 IN A 10.0.0.3",
		},
		dns.TypeTXT: {
			`mxmustfail. 0 IN TXT "ok"`,
		},
	}))
	defer dns.HandleRemove("mxmustfail.")

	{
		r := NewLimitedResolver(testResolver, 2, 2, 2)
		a, _, err := r.LookupTXT("domain.")
		if len(a) == 0 || err != nil {
			t.Error("failed on 1st LookupTXT")
		}
		a, _, err = r.LookupTXT("domain.")
		if len(a) == 1 && err != nil {
			t.Errorf("failed on 2nd LookupTXT with %v", err)
		}
	}
	{
		r := NewLimitedResolver(testResolver, 2, 2, 2)
		b, _, err := r.Exists("domain.")
		if !b || err != nil {
			t.Error("failed on 1st Exists")
		}
		b, _, err = r.Exists("domain.")
		if b || err != ErrDNSLimitExceeded {
			t.Error("failed on 2nd Exists")
		}
	}
	newMatcher := func(matchingIP net.IP) func(net.IP, string) (bool, error) {
		return func(ip net.IP, _ string) (bool, error) {
			return ip.Equal(matchingIP), nil
		}
	}
	{
		r := NewLimitedResolver(testResolver, 2, 2, 2)
		b, _, err := r.MatchIP("domain.", newMatcher(net.ParseIP("10.0.0.1")))
		if !b || err != nil {
			t.Error("failed on 1st MatchIP")
		}
		b, _, err = r.MatchIP("domain.", newMatcher(net.ParseIP("10.0.0.1")))
		if b || err != ErrDNSLimitExceeded {
			t.Error("failed on 2nd MatchIP")
		}
	}
	{
		r := NewLimitedResolver(testResolver, 2, 2, 2)
		b, _, err := r.MatchMX("domain.", newMatcher(net.ParseIP("10.0.0.1")))
		if !b || err != nil {
			t.Error("failed on 1st MatchMX")
		}
		b, _, err = r.MatchMX("domain.", newMatcher(net.ParseIP("10.0.0.1")))
		if b || err != ErrDNSLimitExceeded {
			t.Error("failed on 2nd MatchMX")
		}
	}
	{
		r := NewLimitedResolver(testResolver, 2, 2, 2)
		b, _, err := r.MatchMX("mxmustfail.", newMatcher(net.ParseIP("10.0.0.10")))
		if b || err != ErrDNSLimitExceeded {
			t.Errorf("MatchMX got: %v, %v; want false, ErrDNSLimitExceeded", b, err)
		}
	}
	{
		dns.HandleFunc("void.test.", Zone(map[uint16][]string{}))
		defer dns.HandleRemove("void.test.")
		dns.HandleFunc("non-void.test.", Zone(map[uint16][]string{
			dns.TypeTXT: {
				`non-void.test. 0 IN TXT "ok"`,
			},
		}))
		defer dns.HandleRemove("non-void.test.")

		r := NewLimitedResolver(testResolver, 6, 6, 2)
		_, _, err := r.LookupTXTStrict("void.test.")
		if err != nil {
			t.Errorf("LookupTXTStrict expected err=nil, got: %v", err)
		}

		_, _, err = r.LookupTXTStrict("void.test.")
		if err != nil {
			t.Errorf("LookupTXTStrict expected err=nil, got: %v", err)
		}

		res, _, err := r.LookupTXTStrict("non-void.test.")
		if err != nil {
			t.Errorf("LookupTXTStrict expected err=nil, got: %v", err)
		}

		if len(res) == 0 {
			t.Error("LookupTXTStrict result is empty")
		}

		_, _, err = r.LookupTXTStrict("void.test.")
		if err != ErrDNSVoidLookupLimitExceeded {
			t.Errorf("LookupTXTStrict got: %v; want ErrDNSVoidLookupLimitExceeded", err)
		}
	}
}
