package spf

import (
	"fmt"
	"strings"
	"testing"
)

/*
type spfTestpair struct {
	query    []string
	expected bool
}

type SPFTestCase struct {
	Host string
	Txt  []string
}

//TestSPFLookup ensures a TXT records are properly queried and reurned to the called. Function should also work with
// multiple TXT records for a given host.
func TestSPFLookup(t *testing.T) {
	testcases := []SPFTestCase{
		SPFTestCase{"multi.spf.matching.com", []string{"v=spf1 ip6:2001:db8:a0b:12f0::1 -all", "v=spf1 mx -all"}},
		SPFTestCase{"1.spf.matching.com", []string{"v=spf1 a mx -all"}},
		SPFTestCase{"2.spf.matching.com", []string{"v=spf1 ip4:172.100.100.100 -all"}},
		SPFTestCase{"3.spf.matching.com", []string{"v=spf1 ip4:172.100.100.1/24 ?all"}},
	}

	for _, testcase := range testcases {
		lookup, err := LookupSPF(testcase.Host)
		// There is no guarantee in which order TXT records will be returned for a given host, so we need to sort here
		// in order to ensure the expected ordering will be provided (expected is sorted here)
		sort.Strings(lookup)
		if err != nil {
			t.Error("Caught error: ", err)
		} else if reflect.DeepEqual(testcase.Txt, lookup) == false {
			t.Error("Host: ", testcase.Host, " expected: ", testcase.Txt, " got: ", lookup)
		}
	}
}

func TestSPFLookupNegative(t *testing.T) {
	testcase := SPFTestCase{"incorrect.spf.matching.com", nil}

	spfPrefix := "Invalid SPF record:"
	_, err := LookupSPF(testcase.Host)
	if strings.HasPrefix(err.Error(), spfPrefix) == false {
		t.Error("Expected error to start with: ", spfPrefix, " got: ", err.Error(), " instead.")
	}
}

func TestHandleNoSuchHostDNSError(t *testing.T) {
	host := "idontexist.matching.com"
	_, err := LookupSPF(host)
	switch err.(type) {
	case *net.DNSError:
		break
	default:
		t.Errorf("Expected 'net.DNSError' error type, instead got:  %T\n", err)
	}
}
*/

func TestIsDomainName(t *testing.T) {
	z := func(n int) string { return strings.Repeat("z", n) }

	tests := []struct {
		domain string
		want   bool
	}{
		// RFC 2181, section 11.
		{"_xmpp-server._tcp.google.com", true},
		{"foo.com", true},
		{"1foo.com", true},
		{"26.0.0.73.com", true},
		{"fo-o.com", true},
		{"fo1o.com", true},
		{"foo1.com", true},
		{"a.b..com", false},
		{"a.b-.com", false},
		{"a.b.com-", false},
		{"a.b..", false},
		{"b.com.", true},
		{"unknown", true},
		{strings.Join([]string{"63", z(63), "com"}, "."), true},
		{strings.Join([]string{"64", z(64), "com"}, "."), false},
		{strings.Join([]string{"253", z(53), z(63), z(63), z(63), "com"}, "."), true},
		{strings.Join([]string{"254", z(54), z(63), z(63), z(63), "com"}, "."), false},
		{strings.Join([]string{"254dot", z(50), z(63), z(63), z(63), "com."}, "."), true},
	}

	const skipAllBut = -1
	for no, test := range tests {
		if skipAllBut != -1 && skipAllBut != no {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", no, test.domain), func(t *testing.T) {
			if isDomainName(test.domain) != test.want {
				t.Errorf("isDomainName(%q) = %v; want %v", test.domain, !test.want, test.want)
			}
		})
	}
}

func TestTruncateFQDN(t *testing.T) {
	z := func(n int) string { return strings.Repeat("z", n) }

	tests := []struct {
		fqdn    string
		want    string
		wantErr bool
	}{
		{"1.com", "1.com", false},
		{z(254), "", true},
		{strings.Join([]string{"253", z(245), "com"}, "."),
			strings.Join([]string{"253", z(245), "com"}, "."), false},
		{strings.Join([]string{"254", z(246), "com"}, "."),
			strings.Join([]string{z(246), "com"}, "."), false},
		{strings.Join([]string{"254dot", z(242), "com."}, "."),
			strings.Join([]string{"254dot", z(242), "com."}, "."), false},
		{strings.Join([]string{"a", "b", z(247), "com"}, "."),
			strings.Join([]string{"b", z(247), "com"}, "."), false},
		{strings.Join([]string{"a", "bb", z(247), "com"}, "."),
			strings.Join([]string{z(247), "com"}, "."), false},
		{"net.._l",
			"", true},
		{strings.Join([]string{"64dotdot253.com", z(200), "", z(64), "com"}, "."),
			"", true},
	}

	const skipAllBut = -1
	for no, test := range tests {
		if skipAllBut != -1 && skipAllBut != no {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", no, test.fqdn), func(t *testing.T) {
			got, err := truncateFQDN(test.fqdn)
			if test.wantErr != (err != nil) {
				t.Errorf("truncateFQDN(%q) err=%v, wantErr=%t", test.fqdn, err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("truncateFQDN(%q) = %q; want %q", test.fqdn, got, test.want)
			}
		})
	}
}
