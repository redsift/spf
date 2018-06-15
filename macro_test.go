package spf

import (
	"net"
	"testing"

	"time"

	"fmt"

	"github.com/miekg/dns"
)

const (
	domain = "matching.com"
	sender = "sender@domain.com"
)

var (
	ip4 = net.IP{10, 11, 12, 13}
	tkn = &token{mechanism: tExp, qualifier: qMinus, value: ""}
)

type MacroTest struct {
	Input  string
	Output string
}

func TestMacroIteration(t *testing.T) {
	tests := []struct {
		macro  string
		sender string
		domain string
		addr   net.IP
		want   string
	}{
		{"matching.com", sender, domain, ip4, "matching.com"},
		{"%%matching.com", sender, domain, ip4, "%matching.com"},
		{"%%matching%_%%.com", sender, domain, ip4, "%matching %.com"},
		{"matching%-.com", sender, domain, ip4, "matching%20.com"},
		{"%%%%%_%-", sender, domain, ip4, "%% %20"},
		{"Please email to %{s} end", sender, domain, ip4, "Please email to sender@domain.com end"},
		{"Please email to %{l} end", sender, domain, ip4, "Please email to sender end"},
		// Note also that if the original <sender> had no local-part, the
		// local-part was set to "postmaster" in initial processing (see
		// Section 4.3).
		{"Please email to %{s} end", "example.com", domain, ip4, "Please email to example.com end"},
		{"Please email to %{l} end", "example.com", domain, ip4, "Please email to postmaster end"},
		{"Please email to %{o} end", sender, domain, ip4, "Please email to domain.com end"},
		{"domain %{d} end", sender, domain, ip4, "domain matching.com end"},
		{"Address IP %{i} end", sender, domain, ip4, "Address IP 10.11.12.13 end"},
		{"Address IP %{i1} end", sender, domain, ip4, "Address IP 13 end"},
		{"Address IP %{i100} end", sender, domain, ip4, "Address IP 10.11.12.13 end"},
		{"Address IP %{ir} end", sender, domain, ip4, "Address IP 13.12.11.10 end"},
		{"Address IP %{i2r} end", sender, domain, ip4, "Address IP 11.10 end"},
		{"Address IP %{i500r} end", sender, domain, ip4, "Address IP 13.12.11.10 end"},
	}

	const skipAllBut = -1
	for no, test := range tests {
		if skipAllBut != -1 && skipAllBut != no {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", no, test.domain), func(t *testing.T) {
			got, err := parseMacroToken(
				newParser(WithResolver(testResolver)).with(stub, test.sender, test.domain, test.addr),
				&token{mechanism: tExp, qualifier: qMinus, value: test.macro})

			if err != nil {
				t.Errorf("'%s' err=%s", test.macro, err)
			}
			if got != test.want {
				t.Errorf("'%s' got=%q, want=%q", test.macro, got, test.want)
			}
		})
	}
}

// TestMacroExpansionRFCExamples will execute examples from RFC 7208, section
// 7.4
func TestMacroExpansionRFCExamples(t *testing.T) {
	testCases := []*MacroTest{
		{"", ""},
		{"%{s}", "strong-bad@email.example.com"},
		{"%{o}", "email.example.com"},
		{"%{d}", "email.example.com"},
		{"%{d4}", "email.example.com"},
		{"%{d3}", "email.example.com"},
		{"%{d2}", "example.com"},
		{"%{d1}", "com"},
		{"%{dr}", "com.example.email"},
		{"%{d2r}", "example.email"},
		{"%{l}", "strong-bad"},
		{"%{l-}", "strong.bad"},
		{"%{lr}", "strong-bad"},
		{"%{lr-}", "bad.strong"},
		{"%{l1r-}", "strong"},
		{"%{ir}.%{v}._spf.%{d2}",
			"3.2.0.192.in-addr._spf.example.com"},
		{"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
		{"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
			"bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
		{"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
			"3.2.0.192.in-addr.strong.lp._spf.example.com"},
		{"%{d2}.trusted-domains.example.net",
			"example.com.trusted-domains.example.net"},
		{"%{S}", "strong-bad@email.example.com"},
		{"%{O}", "email.example.com"},
		{"%{D}", "email.example.com"},
		{"%{D4}", "email.example.com"},
		{"%{Dr}", "com.example.email"},
		{"%{dR}", "com.example.email"},
		{"%{DR}", "com.example.email"},
		{"%{D2R}", "example.email"},
		{"%{L}", "strong-bad"},
		{"%{IR}.%{V}._spf.%{D2}",
			"3.2.0.192.in-addr._spf.example.com"},
	}

	parser := newParser(WithResolver(testResolver)).
		with(stub, "strong-bad@email.example.com", "email.example.com", net.IP{192, 0, 2, 3})

	for _, test := range testCases {

		tkn.value = test.Input
		result, err := parseMacroToken(parser, tkn)
		if err != nil {
			t.Errorf("Macro %s evaluation failed due to returned error: %v\n",
				test.Input, err)
		}
		if result != test.Output {
			t.Errorf("Macro '%s', evaluation failed, got: '%s',\nexpected '%s'\n",
				test.Input, result, test.Output)
		}
	}
}

// TODO(zaccone): Fill epected error messages and compare with those returned.
func TestParsingErrors(t *testing.T) {
	testcases := []*MacroTest{
		{"%", ""},
		{"%{?", ""},
		{"%}", ""},
		{"%a", ""},
		{"%", ""},
		{"%{}", ""},
		{"%{", ""},
		{"%{234", ""},
		{"%{2a3}", ""},
		{"%{i2", ""},
		{"%{s2a3}", ""},
		{"%{s2i3}", ""},
		{"%{s2ir-3}", ""},
		{"%{l2a3}", ""},
		{"%{i2a3}", ""},
		{"%{o2a3}", ""},
		{"%{d2a3}", ""},
		{"%{i-2}", ""},
	}

	parser := newParser(WithResolver(testResolver)).with(stub, sender, domain, ip4)

	for _, test := range testcases {

		tkn.value = test.Input
		result, err := parseMacroToken(parser, tkn)

		if result != "" {
			t.Errorf("For input '%s' expected empty result, got '%s' instead\n",
				test.Input, result)
		}

		if err == nil {
			t.Errorf("For input '%s', expected non-empty err, got nil instead and result '%s'\n",
				test.Input, result)
		}
	}
}

func TestMacro_Domains(t *testing.T) {
	//	For recursive evaluations, the domain portion of <sender> might not
	//be the same as the <domain> argument when check_host() is initially
	//evaluated.  In most other cases it will be the same (see Section 5.2
	//below).
	testResolverCache.Purge()

	dns.HandleFunc("a.test.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`a.test. 0 IN TXT "v=spf1 include:positive.%{d} -all"`,
		},
	}))
	defer dns.HandleRemove("a.test.")

	dns.HandleFunc("positive.a.test.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`positive.a.test. 0 IN TXT "v=spf1 +all"`,
		},
	}))
	defer dns.HandleRemove("positive.a.test.")

	dns.HandleFunc("b.test.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`b.test. 0 IN TXT "v=spf1 include:positive.%{O} -all"`,
		},
	}))
	defer dns.HandleRemove("b.test.")

	dns.HandleFunc("positive.b.test.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`positive.b.test. 0 IN TXT "v=spf1 -all"`,
		},
	}))
	defer dns.HandleRemove("positive.b.test.")

	parseTestCases := []parseTestCase{
		{"v=spf1 include:a.test -all", net.IP{127, 0, 0, 1}, Pass},
		{"v=spf1 include:b.test -all", net.IP{127, 0, 0, 1}, Pass},
	}

	for _, testcase := range parseTestCases {
		type R struct {
			r Result
			e error
		}
		done := make(chan R)
		go func() {
			result, _, err, _ :=
				newParser(WithResolver(NewLimitedResolver(testResolver, 4, 4))).
					with(testcase.Query, "a.test", "c.test", testcase.IP).
					check()
			done <- R{result, err}
		}()
		select {
		case <-time.After(5 * time.Second):
			t.Errorf("%q failed due to timeout", testcase.Query)
		case r := <-done:
			if r.r != Permerror && r.r != Temperror && r.e != nil {
				t.Errorf("%q Unexpected error while parsing: %s", testcase.Query, r.e)
			}
			if r.r != testcase.Result {
				t.Errorf("%q Expected %v, got %v", testcase.Query, testcase.Result, r.r)
			}
			continue
		}
	}
}
