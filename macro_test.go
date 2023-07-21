package spf

import (
	"fmt"
	. "github.com/redsift/spf/v2/testing"
	"net"
	"testing"
	"time"

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
		{"Address IPv6 %{i} end", sender, domain, net.ParseIP("1000::ff"), "Address IPv6 10.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ff end"},
		{"Address IPv6 %{ir} end", sender, domain, net.ParseIP("1000::ff"), "Address IPv6 ff.0.0.0.0.0.0.0.0.0.0.0.0.0.0.10 end"},
		{"Address IP %{i1} end", sender, domain, ip4, "Address IP 13 end"},
		{"Address IP %{i100} end", sender, domain, ip4, "Address IP 10.11.12.13 end"},
		{"Address IP %{ir} end", sender, domain, ip4, "Address IP 13.12.11.10 end"},
		{"Address IP %{i2r} end", sender, domain, ip4, "Address IP 11.10 end"},
		{"Address IP %{i500r} end", sender, domain, ip4, "Address IP 13.12.11.10 end"},
	}

	const skipAllBut = -1
	for no, test := range tests {
		if //goland:noinspection GoBoolExpressions
		skipAllBut != -1 && skipAllBut != no {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", no, test.domain), func(t *testing.T) {
			got, _, err := parseMacroToken(
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
		{
			"%{ir}.%{v}._spf.%{d2}",
			"3.2.0.192.in-addr._spf.example.com",
		},
		{"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
		{
			"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
			"bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
		},
		{
			"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}",
			"3.2.0.192.in-addr.strong.lp._spf.example.com",
		},
		{
			"%{d2}.trusted-domains.example.net",
			"example.com.trusted-domains.example.net",
		},
		{"%{S}", "strong-bad@email.example.com"},
		{"%{O}", "email.example.com"},
		{"%{D}", "email.example.com"},
		{"%{D4}", "email.example.com"},
		{"%{Dr}", "com.example.email"},
		{"%{dR}", "com.example.email"},
		{"%{DR}", "com.example.email"},
		{"%{D2R}", "example.email"},
		{"%{L}", "strong-bad"},
		{
			"%{IR}.%{V}._spf.%{D2}",
			"3.2.0.192.in-addr._spf.example.com",
		},
	}

	parser := newParser(WithResolver(testResolver)).
		with(stub, "strong-bad@email.example.com", "email.example.com", net.IP{192, 0, 2, 3})

	for _, test := range testCases {

		tkn.value = test.Input
		result, _, err := parseMacroToken(parser, tkn)
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

func TestMacroExpansion_partial(t *testing.T) {
	testCases := []*MacroTest{
		{"%{h}.%{d}", "%{h}.email.example.com"},
		{"%{h}.%{dr}", "%{h}.com.example.email"},
		{"prefix.%{h}.%{d}", "prefix.%{h}.email.example.com"},
		{"%{h}.%{d}.postfix", "%{h}.email.example.com.postfix"},
		{"%{h}.main.%{d}", "%{h}.main.email.example.com"},
		{"%{h}.%%.%{d}", "%{h}.%%.email.example.com"},
		{"%{h}.%_.%{d}", "%{h}.%_.email.example.com"},
		{"%{h}.%-.%{d}", "%{h}.%-.email.example.com"},
	}

	parser := newParser(WithResolver(testResolver), PartialMacros(true)).
		with(stub, "strong-bad@email.example.com", "email.example.com", net.IP{192, 0, 2, 3})

	for _, test := range testCases {

		tkn.value = test.Input
		result, _, err := parseMacroToken(parser, tkn)
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
		result, _, err := parseMacroToken(parser, tkn)

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
	// For recursive evaluations, the domain portion of <sender> might not
	// be the same as the <domain> argument when check_host() is initially
	// evaluated.  In most other cases it will be the same (see Section 5.2
	// below).
	testResolverCache.Clear()

	dns.HandleFunc("a.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`a.test. 0 IN TXT "v=spf1 include:positive.%{d} -all"`,
		},
	}))
	defer dns.HandleRemove("a.test.")

	dns.HandleFunc("positive.a.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`positive.a.test. 0 IN TXT "v=spf1 +all"`,
		},
	}))
	defer dns.HandleRemove("positive.a.test.")

	dns.HandleFunc("b.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`b.test. 0 IN TXT "v=spf1 include:positive.%{O} -all"`,
		},
	}))
	defer dns.HandleRemove("b.test.")

	dns.HandleFunc("positive.b.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`positive.b.test. 0 IN TXT "v=spf1 -all"`,
		},
	}))
	defer dns.HandleRemove("positive.b.test.")

	dns.HandleFunc("c.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`c.test. 0 IN TXT "v=spf1 include:%{h} -all"`,
		},
	}))
	defer dns.HandleRemove("c.test.")

	dns.HandleFunc("positive.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`positive.test. 0 IN TXT "v=spf1 +all"`,
		},
	}))
	defer dns.HandleRemove("positive.test.")

	dns.HandleFunc("c.explain.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`c.explain.test. 0 IN TXT "%{c}"`,
		},
	}))
	defer dns.HandleRemove("c.explain.test.")

	dns.HandleFunc("r.explain.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`r.explain.test. 0 IN TXT "%{r}"`,
		},
	}))
	defer dns.HandleRemove("r.explain.test.")

	dns.HandleFunc("t.explain.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`t.explain.test. 0 IN TXT "%{t}"`,
		},
	}))
	defer dns.HandleRemove("t.explain.test.")

	tests := []struct {
		query         string
		helo          string
		receivingFQDN string
		want          Result
		wantExp       string
		wantErr       bool
		partial       bool
	}{
		{"v=spf1 include:a.test -all", "", "", Pass, "", false, false},
		{"v=spf1 include:b.test -all", "", "", Pass, "", false, false},
		{"v=spf1 include:c.test -all", "positive.test", "", Pass, "", false, false},
		{"v=spf1 -all exp=c.explain.test", "positive.test", "", Fail, "1000::1", false, false},
		{"v=spf1 -all exp=r.explain.test", "positive.test", "example.com", Fail, "example.com", false, false},
		{"v=spf1 -all exp=t.explain.test", "positive.test", "", Fail, "1", false, false},
		{"v=spf1 -all exp=r.explain.test", "positive.test", "", Fail, "unknown", false, false},
		{"v=spf1 include:%{c}", "positive.test", "", Permerror, "", true, false},
		{"v=spf1 include:%{r}", "positive.test", "", Permerror, "", true, false},
		{"v=spf1 include:%{t}", "positive.test", "", Permerror, "", true, false},
		{"v=spf1 include:a.test -all", "", "", Pass, "", false, true},
	}

	const skipAllBut = -1
	for no, test := range tests {
		if //goland:noinspection GoBoolExpressions
		skipAllBut != -1 && skipAllBut != no {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", no, test.query), func(t *testing.T) {
			got, exp, _, err := newParser(WithResolver(NewLimitedResolver(testResolver, 4, 4)),
				HeloDomain(test.helo),
				EvaluatedOn(time.Unix(1, 0)),
				ReceivingFQDN(test.receivingFQDN)).
				with(test.query, "a.test", "c.test", net.ParseIP("1000:0000:0000:0000:0000:0000:0000:0001")).
				check()
			if test.wantErr != (err != nil) {
				t.Errorf("%q err=%s", test.query, err)
			}
			if got != test.want {
				t.Errorf("%q got=%v, want=%v", test.query, got, test.want)
			}
			if exp != test.wantExp {
				t.Errorf("%q exp=%q, wantExp=%q", test.query, exp, test.wantExp)
			}
		})
	}
}
