package spf

import (
	"errors"
	"fmt"
	"github.com/redsift/spf/v2/spferr"
	. "github.com/redsift/spf/v2/testing"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
)

const (
	stub string = "stub"
)

var (
	ip   = net.IP{127, 0, 0, 1}
	ipv6 = net.ParseIP("2001:4860:0:2001::68")
)

/* helper functions */

/********************/

func TestNewParserFunction(t *testing.T) {
	p := newParser(WithResolver(testResolver)).with(stub, stub, stub, ip)

	if p.sender != stub {
		t.Error("sender mismatch, got: ", p.sender, " expected ", stub)
	}
	if p.domain != stub {
		t.Error("domain mismatch, got: ", p.domain, " expected ", stub)
	}
	if p.query != stub {
		t.Error("query mismatch, got: ", p.query, " expected ", stub)
	}
	if !ip.Equal(p.ip) {
		t.Error("IP mismatch, got: ", p.ip, " expected ", ip)
	}
}

func TestMatchingResult(t *testing.T) {
	type TestCase struct {
		Qualifier tokenType
		Result    Result
	}

	testcases := []TestCase{
		{qPlus, Pass},
		{qMinus, Fail},
		{qQuestionMark, Neutral},
		{qTilde, Softfail},
	}

	var result Result
	var err error
	for _, testcase := range testcases {
		result, err = matchingResult(testcase.Qualifier)
		if err != nil {
			t.Error("Qualifier ", testcase.Qualifier, " returned error: ",
				err, " (it shouldn't)")
		}
		if result != testcase.Result {
			t.Error("Expected result ", testcase.Result, " got ", result)
		}
	}

	// ensure an error will be returned upon invalid qualifier
	result, err = matchingResult(tAll)
	if err == nil {
		t.Error("matchingResult expected to fail")
	}

	if result != internalError {
		t.Error(`Upon failure matchingResult expected to return result SPFEnd,
                 instead got `, result)
	}
}

func TestTokensSoriting(t *testing.T) {
	// stub := "stub"
	versionToken := &token{mechanism: tVersion, qualifier: qPlus, value: "spf1"}
	type TestCase struct {
		Tokens      []*token
		ExpTokens   []*token
		Redirect    *token
		Explanation *token
	}

	testcases := []TestCase{
		{
			[]*token{
				versionToken,
				{mechanism: tAll, qualifier: qMinus, value: ""},
			},
			[]*token{
				versionToken,
				{mechanism: tAll, qualifier: qMinus, value: ""},
			},
			nil,
			nil,
		},
		{
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tMX, qualifier: qTilde, value: "example.org"},
			},
			[]*token{
				versionToken,
				{mechanism: tMX, qualifier: qTilde, value: "example.org"},
			},
			&token{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
			nil,
		},
		{
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tIP4, qualifier: qTilde, value: "192.168.1.2"},
				{mechanism: tExp, qualifier: qPlus, value: "Something went wrong"},
			},
			[]*token{
				versionToken,
				{mechanism: tIP4, qualifier: qTilde, value: "192.168.1.2"},
			},
			&token{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
			&token{mechanism: tExp, qualifier: qPlus, value: "Something went wrong"},
		},
		{
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tMX, qualifier: qTilde, value: "example.org"},
				{mechanism: tAll, qualifier: qQuestionMark, value: ""},
			},
			[]*token{
				versionToken,
				{mechanism: tMX, qualifier: qTilde, value: "example.org"},
				{mechanism: tAll, qualifier: qQuestionMark, value: ""},
			},
			&token{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
			nil,
		},
		{
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tMX, qualifier: qTilde, value: "example.org"},
				{mechanism: tAll, qualifier: qQuestionMark, value: ""},
				{mechanism: tExp, qualifier: qPlus, value: "You are wrong"},
			},
			[]*token{
				versionToken,
				{mechanism: tMX, qualifier: qTilde, value: "example.org"},
				{mechanism: tAll, qualifier: qQuestionMark, value: ""},
			},
			&token{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
			&token{mechanism: tExp, qualifier: qPlus, value: "You are wrong"},
		},
	}

	for _, testcase := range testcases {
		mechanisms, redirect, explanation, _ := sortTokens(testcase.Tokens)

		if !reflect.DeepEqual(mechanisms, testcase.ExpTokens) {
			t.Error("mechanisms mistmatch, got: ", mechanisms,
				" expected: ", testcase.ExpTokens)
		}
		if !reflect.DeepEqual(redirect, testcase.Redirect) {
			t.Error("Expected Redirect to be", testcase.Redirect,
				" got ", redirect)
		}
		if !reflect.DeepEqual(explanation, testcase.Explanation) {
			t.Error("Expected Explanation to be", testcase.Explanation,
				" got ", explanation, " testcase ", explanation, redirect)
		}
	}
}

func TestTokensSoritingHandleErrors(t *testing.T) {
	versionToken := &token{mechanism: tVersion, qualifier: qPlus, value: "spf1"}
	type TestCase struct {
		Tokens []*token
	}

	testcases := []TestCase{
		{
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tMX, qualifier: qMinus, value: "example.org"},
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
			},
		},
		{
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tMX, qualifier: qMinus, value: "example.org"},
				{mechanism: tExp, qualifier: qPlus, value: "Explanation"},
				{mechanism: tExp, qualifier: qPlus, value: "Explanation"},
			},
		},
		{
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tAll, qualifier: qMinus, value: ""},
				{mechanism: tExp, qualifier: qPlus, value: "_spf.example.com"},
				{mechanism: tRedirect, qualifier: qPlus, value: "mydomain.com"},
			},
		},
	}

	for _, testcase := range testcases {
		if _, _, _, err := sortTokens(testcase.Tokens); err == nil {
			t.Error("We should have gotten an error, ")
		}
	}
}

/* Test Parse.parse* methods here */

type TokenTestCase struct {
	Input         *token
	Result        Result
	Match         bool
	ignoreMatches bool
}

type TokenTestCaseWithTTL struct {
	Input  *token
	Result Result
	Match  bool
	Ttl    time.Duration
}

// TODO(marek): Add testfunction for tVersion token

func TestParseAll(t *testing.T) {
	testcases := []TokenTestCase{
		{&token{mechanism: tAll, qualifier: qPlus, value: ""}, Pass, true, false},
		{&token{mechanism: tAll, qualifier: qMinus, value: ""}, Fail, true, false},
		{&token{mechanism: tAll, qualifier: qQuestionMark, value: ""}, Neutral, true, false},
		{&token{mechanism: tAll, qualifier: qTilde, value: ""}, Softfail, true, false},
		{&token{mechanism: tAll, qualifier: tErr, value: ""}, Permerror, true, false},
		{&token{mechanism: tAll, qualifier: qPlus, value: ""}, Pass, true, true},
		{&token{mechanism: tAll, qualifier: qPlus, value: ""}, Pass, true, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		opts := []Option{WithResolver(testResolver)}
		if testcase.ignoreMatches {
			opts = append(opts, IgnoreMatches())
		}

		p := newParser(opts...).with(stub, stub, stub, ip)

		match, result, _ = p.parseAll(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseA(t *testing.T) {
	dns.HandleFunc("matching.com.", Zone(map[uint16][]string{
		dns.TypeA: {
			"matching.com. 2 IN A 172.20.21.1",
			"matching.com. 20 IN A 172.18.0.2",
			"matching.com. 5 IN A 172.20.20.1",
		},
		dns.TypeAAAA: {
			"matching.com. 2 IN AAAA 2001:4860:0:2001::68",
		},
	}))
	defer dns.HandleRemove("matching.com.")

	dns.HandleFunc("positive.matching.com.", Zone(map[uint16][]string{
		dns.TypeA: {
			"positive.matching.com. 2 IN A 172.20.21.1",
			"positive.matching.com. 20 IN A 172.18.0.2",
			"positive.matching.com. 100 IN A 172.20.20.1",
		},
		dns.TypeAAAA: {
			"positive.matching.com. 2 IN AAAA 2001:4860:0:2001::68",
		},
	}))
	defer dns.HandleRemove("positive.matching.com.")

	dns.HandleFunc("negative.matching.com.", Zone(map[uint16][]string{
		dns.TypeA: {
			"negative.matching.com. 2 IN A 172.20.21.1",
		},
	}))
	defer dns.HandleRemove("negative.matching.com.")

	dns.HandleFunc("range.matching.com.", Zone(map[uint16][]string{
		dns.TypeA: {
			"range.matching.com. 2 IN A 172.18.0.2",
		},
	}))
	defer dns.HandleRemove("range.matching.com.")

	dns.HandleFunc("lb.matching.com.", Zone(map[uint16][]string{
		dns.TypeA: {
			"lb.matching.com. 2 IN A 172.18.0.2",
		},
	}))
	defer dns.HandleRemove("lb.matching.com.")

	p := newParser(WithResolver(testResolver)).with(stub, domain, "matching.com", net.IP{172, 18, 0, 2})
	testcases := []TokenTestCaseWithTTL{
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/32"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "negative.matching.com"}, Pass, false, 0},
		{&token{mechanism: tA, qualifier: qPlus, value: "range.matching.com/16"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "range.matching.com/128"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "idontexist"}, Pass, false, 0},
		{&token{mechanism: tA, qualifier: qPlus, value: "#%$%^"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "lb.matching.com"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qMinus, value: ""}, Fail, true, 0},
		{&token{mechanism: tA, qualifier: qTilde, value: ""}, Softfail, true, 0},

		// expect (Permerror, true) results as a result of syntax errors
		{&token{mechanism: tA, qualifier: qPlus, value: "range.matching.com/wrongmask"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "range.matching.com/129"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "range.matching.com/-1"}, Permerror, true, 2},

		// expect (Permerror, true) due to wrong netmasks.
		// It's a syntax error to specify a netmask over 32 bits for IPv4 addresses
		{&token{mechanism: tA, qualifier: qPlus, value: "negative.matching.com/128"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/128"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/128"}, Permerror, true, 2},

		// test dual-cidr syntax
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com//128"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/32/"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/0/0"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/24/24"}, Pass, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/33/100"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/24/129"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/128/32"}, Permerror, true, 2},
		{&token{mechanism: tA, qualifier: qPlus, value: "//32"}, Pass, true, 2},
	}

	var match bool
	var result Result
	for _, testcase := range testcases {
		t.Run(testcase.Input.value, func(t *testing.T) {
			match, result, _, _ = p.parseA(testcase.Input)
			if testcase.Match != match {
				t.Errorf("Want 'Match' %v, got %v", testcase.Match, match)
			}
			if testcase.Result != result {
				t.Errorf("Want 'Result' %v, got %v", testcase.Result, result)
			}
		})
	}
}

func TestParseAIpv6(t *testing.T) {
	hosts := make(map[uint16][]string)

	hosts[dns.TypeA] = []string{
		"positive.matching.com. 0 IN A 172.20.21.1",
		"positive.matching.com. 0 IN A 172.18.0.2",
		"positive.matching.com. 0 IN A 172.20.20.1",
	}
	hosts[dns.TypeAAAA] = []string{
		"positive.matching.com. 0 IN AAAA 2001:4860:0:2001::68",
	}

	positiveMatchingCom := Zone(hosts)
	dns.HandleFunc("positive.matching.com.", positiveMatchingCom)
	defer dns.HandleRemove("positive.matching.com.")
	dns.HandleFunc("matching.com.", positiveMatchingCom)
	defer dns.HandleRemove("matching.com.")

	hosts = make(map[uint16][]string)

	hosts[dns.TypeA] = []string{
		"negative.matching.com. 0 IN A 172.20.21.1",
	}
	negativeMatchingCom := Zone(hosts)
	dns.HandleFunc("negative.matching.com.", negativeMatchingCom)
	defer dns.HandleRemove("negative.matching.com.")

	testcases := []TokenTestCase{
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com"}, Pass, true, false},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com//128"}, Pass, true, false},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com//64"}, Pass, true, false},

		{&token{mechanism: tA, qualifier: qPlus, value: "negative.matching.com"}, Pass, false, false},
		{&token{mechanism: tA, qualifier: qPlus, value: "negative.matching.com//64"}, Pass, false, false},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com// "}, Permerror, true, false},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/ "}, Permerror, true, false},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/ / "}, Permerror, true, false},

		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com"}, Pass, true, true},
		{&token{mechanism: tA, qualifier: qPlus, value: "negative.matching.com"}, Pass, false, true},
		{&token{mechanism: tA, qualifier: qPlus, value: "positive.matching.com/ / "}, Permerror, true, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		t.Run(testcase.Input.value, func(t *testing.T) {
			opts := []Option{WithResolver(testResolver)}
			if testcase.ignoreMatches {
				opts = append(opts, IgnoreMatches())
			}

			p := newParser(opts...).with(stub, domain, "matching.com", ipv6)

			match, result, _, _ = p.parseA(testcase.Input)
			if testcase.Match != match {
				t.Errorf("Want 'Match' %v, got %v", testcase.Match, match)
			}
			if testcase.Result != result {
				t.Errorf("Want 'Result' %v, got %v", testcase.Result, result)
			}
		})
	}
}

func TestParseIp4(t *testing.T) {
	testcases := []TokenTestCase{
		{&token{mechanism: tIP4, qualifier: qPlus, value: "127.0.0.1"}, Pass, true, false},
		{&token{mechanism: tIP4, qualifier: qMinus, value: "127.0.0.1"}, Fail, true, false},
		{&token{mechanism: tIP4, qualifier: qQuestionMark, value: "127.0.0.1"}, Neutral, true, false},
		{&token{mechanism: tIP4, qualifier: qTilde, value: "127.0.0.1"}, Softfail, true, false},

		{&token{mechanism: tIP4, qualifier: qTilde, value: "127.0.0.0/16"}, Softfail, true, false},

		{&token{mechanism: tIP4, qualifier: qTilde, value: "192.168.1.2"}, Softfail, false, false},
		{&token{mechanism: tIP4, qualifier: qMinus, value: "192.168.1.5/16"}, Fail, false, false},

		{&token{mechanism: tIP4, qualifier: qMinus, value: "random string"}, Permerror, true, false},
		{&token{mechanism: tIP4, qualifier: qMinus, value: "2001:4860:0:2001::68"}, Permerror, true, false},
		{&token{mechanism: tIP4, qualifier: qMinus, value: "2001:4860:0:2001::68/48"}, Permerror, true, false},

		{&token{mechanism: tIP4, qualifier: qPlus, value: "127.0.0.1"}, Pass, true, true},
		{&token{mechanism: tIP4, qualifier: qMinus, value: "127.0.0.1"}, Fail, true, true},
		{&token{mechanism: tIP4, qualifier: qMinus, value: "random string"}, Permerror, true, true},
		{&token{mechanism: tIP4, qualifier: qMinus, value: "random string"}, Permerror, true, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		opts := []Option{WithResolver(testResolver)}
		if testcase.ignoreMatches {
			opts = append(opts, IgnoreMatches())
		}

		p := newParser(opts...).with(stub, stub, stub, ip)

		match, result, _ = p.parseIP4(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch")
		}
		if testcase.Result != result {
			t.Error("Result mismatch")
		}
	}
}

func TestParseIp6(t *testing.T) {
	testcases := []TokenTestCase{
		{&token{mechanism: tIP6, qualifier: qPlus, value: "2001:4860:0:2001::68"}, Pass, true, false},
		{&token{mechanism: tIP6, qualifier: qMinus, value: "2001:4860:0:2001::68"}, Fail, true, false},
		{&token{mechanism: tIP6, qualifier: qQuestionMark, value: "2001:4860:0:2001::68"}, Neutral, true, false},
		{&token{mechanism: tIP6, qualifier: qTilde, value: "2001:4860:0:2001::68"}, Softfail, true, false},

		{&token{mechanism: tIP6, qualifier: qTilde, value: "2001:4860:0:2001::68/64"}, Softfail, true, false},

		{&token{mechanism: tIP6, qualifier: qTilde, value: "::1"}, Softfail, false, false},
		{&token{mechanism: tIP6, qualifier: qMinus, value: "2002::/16"}, Fail, false, false},

		{&token{mechanism: tIP6, qualifier: qMinus, value: "random string"}, Permerror, true, false},

		{&token{mechanism: tIP6, qualifier: qPlus, value: "2001:4860:0:2001::68"}, Pass, true, true},
		{&token{mechanism: tIP6, qualifier: qMinus, value: "2001:4860:0:2001::68"}, Fail, true, true},
		{&token{mechanism: tIP6, qualifier: qTilde, value: "::1"}, Softfail, false, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		opts := []Option{WithResolver(testResolver)}
		if testcase.ignoreMatches {
			opts = append(opts, IgnoreMatches())
		}

		p := newParser(opts...).with(stub, stub, stub, ipv6)

		match, result, _ = p.parseIP6(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

func TestParseIp6WithIp4(t *testing.T) {
	testcases := []TokenTestCase{
		{&token{mechanism: tIP6, qualifier: qPlus, value: "127.0.0.1"}, Permerror, true, false},
		{&token{mechanism: tIP6, qualifier: qTilde, value: "127.0.0.1"}, Permerror, true, false},

		{&token{mechanism: tIP6, qualifier: qPlus, value: "127.0.0.1"}, Permerror, true, true},
		{&token{mechanism: tIP6, qualifier: qTilde, value: "127.0.0.1"}, Permerror, true, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		opts := []Option{WithResolver(testResolver)}
		if testcase.ignoreMatches {
			opts = append(opts, IgnoreMatches())
		}

		p := newParser(opts...).with(stub, stub, stub, ip)

		match, result, _ = p.parseIP6(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

func TestParseMX(t *testing.T) {
	ips := []net.IP{
		{172, 18, 0, 2},
		{172, 20, 20, 20},
		{172, 100, 0, 1},
		net.ParseIP("2001:4860:1:2001::80"),
	}

	/* helper functions */

	dns.HandleFunc("matching.com.", Zone(map[uint16][]string{
		dns.TypeMX: {
			"matching.com. 2 IN MX 5 mail.matching.com.",
			"matching.com. 100 IN MX 10 mail2.matching.com.",
			"matching.com. 5000 IN MX 15 mail3.matching.com.",
		},
		dns.TypeAAAA: {
			"mail.matching.com. 2 IN AAAA 2001:4860:1:2001::80",
		},
		dns.TypeA: {
			"mail.matching.com. 2 IN A 172.18.0.2",
			"mail2.matching.com. 30 IN A 172.20.20.20",
			"mail3.matching.com. 2 IN A 172.100.0.1",
		},
	}))
	defer dns.HandleRemove("matching.com.")

	/* ***************** */

	p := newParser(WithResolver(testResolver)).with(stub, domain, "matching.com", net.IP{0, 0, 0, 0})

	testcases := []TokenTestCaseWithTTL{
		{&token{mechanism: tMX, qualifier: qPlus, value: "matching.com"}, Pass, true, 2},
		{&token{mechanism: tMX, qualifier: qPlus, value: "matching.com/24"}, Pass, true, 2},
		{&token{mechanism: tMX, qualifier: qPlus, value: "matching.com/24/64"}, Pass, true, 2},
		{&token{mechanism: tMX, qualifier: qPlus, value: "/24"}, Pass, true, 2}, // domain is matching.com.
		{&token{mechanism: tMX, qualifier: qPlus, value: ""}, Pass, true, 0},
		{&token{mechanism: tMX, qualifier: qMinus, value: ""}, Fail, true, 0},
		{&token{mechanism: tMX, qualifier: qPlus, value: "idontexist"}, Pass, false, 0},
		// Mind that the domain is matching.NET and we expect Parser
		// to not match results.
		{&token{mechanism: tMX, qualifier: qPlus, value: "matching.net"}, Pass, false, 0},
		{&token{mechanism: tMX, qualifier: qPlus, value: "matching.net/24"}, Pass, false, 0},
		{&token{mechanism: tMX, qualifier: qPlus, value: "matching.net/24/64"}, Pass, false, 0},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		for _, ip := range ips {
			t.Run(testcase.Input.String()+"/"+ip.String(), func(t *testing.T) {
				p.ip = ip
				match, result, _, _ = p.parseMX(testcase.Input)
				if testcase.Match != match {
					t.Errorf("Want 'Match' %v, got %v", testcase.Match, match)
				}
				if testcase.Result != result {
					t.Errorf("Want 'Result' %v, got %v", testcase.Result, result)
				}
			})
		}
	}
}

func TestParseMXNegativeTests(t *testing.T) {
	/* helper functions */

	hosts := make(map[uint16][]string)

	hosts[dns.TypeMX] = []string{
		"mail.matching.com. 0 IN MX 5 mail.matching.com.",
		"mail.matching.com. 0 IN MX 10 mail2.matching.com.",
		"mail.matching.com. 0 IN MX 15 mail3.matching.com.",
	}
	hosts[dns.TypeAAAA] = []string{
		"mail.matching.com. 0 IN AAAA 2001:4860:1:2001::80",
	}

	hosts[dns.TypeA] = []string{
		"mail.matching.com. 0 IN A 172.18.0.2",
		"mail2.matching.com. 0 IN A 172.20.20.20",
		"mail3.matching.com. 0 IN A 172.100.0.1",
	}
	mxMatchingCom := Zone(hosts)
	dns.HandleFunc("matching.com.", mxMatchingCom)
	defer dns.HandleRemove("matching.com.")

	testcases := []TokenTestCase{
		{&token{mechanism: tMX, qualifier: qPlus, value: "matching.com"}, Pass, false, false},
		{&token{mechanism: tMX, qualifier: qPlus, value: ""}, Pass, false, false},
		// TokenTestCase{&token{tMX, qPlus, "google.com"}, Pass, false},
		{&token{mechanism: tMX, qualifier: qPlus, value: "idontexist"}, Pass, false, false},
		{&token{mechanism: tMX, qualifier: qMinus, value: "matching.com"}, Fail, false, false},

		{&token{mechanism: tMX, qualifier: qPlus, value: "idontexist"}, Pass, false, true},
		{&token{mechanism: tMX, qualifier: qMinus, value: "matching.com"}, Fail, false, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		opts := []Option{WithResolver(testResolver)}
		if testcase.ignoreMatches {
			opts = append(opts, IgnoreMatches())
		}

		p := newParser(opts...).with(stub, "matching.com", "matching.com", net.IP{127, 0, 0, 1})

		match, result, _, _ = p.parseMX(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

/* parseInclude tests */

func TestParseInclude(t *testing.T) {
	/* helper functions */

	dns.HandleFunc("matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`_spf.matching.net. 0 IN TXT "v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all"`,
		},
		dns.TypeMX: {
			"mail.matching.net. 0 IN MX 5 mail.matching.net.",
			"mail.matching.net. 0 IN MX 10 mail2.matching.net.",
		},
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
			"negative.matching.net. 0 IN A 172.18.100.100",
			"negative.matching.net. 0 IN A 172.18.100.101",
			"negative.matching.net. 0 IN A 172.18.100.102",
			"negative.matching.net. 0 IN A 172.18.100.103",
			"mail.matching.net.	0 IN A 173.18.0.2",
			"mail2.matching.net. 0 IN A 173.20.20.20",
		},
	}))
	defer dns.HandleRemove("matching.net.")

	/*******************************/
	ips := []net.IP{
		{172, 100, 100, 1},
		{173, 20, 20, 1},
		{173, 20, 21, 1},
	}

	p := newParser(WithResolver(testResolver)).with(stub, "matching.net", "matching.net", net.IP{0, 0, 0, 0})
	testcases := []TokenTestCase{
		{&token{mechanism: tInclude, qualifier: qPlus, value: "_spf.matching.net"}, Pass, true, false},
		{&token{mechanism: tInclude, qualifier: qMinus, value: "_spf.matching.net"}, Fail, true, false},
		{&token{mechanism: tInclude, qualifier: qTilde, value: "_spf.matching.net"}, Softfail, true, false},
		{&token{mechanism: tInclude, qualifier: qQuestionMark, value: "_spf.matching.net"}, Neutral, true, false},
	}

	for i, testcase := range testcases {
		for j, ip := range ips {
			p.ip = ip
			match, result, _ := p.parseInclude(testcase.Input)
			if testcase.Match != match {
				t.Errorf("#%d.%d Match mismatch, expected %v, got %v", i, j, testcase.Match, match)
			}
			if testcase.Result != result {
				t.Errorf("#%d.%d Result mismatch, expected %v, got %v", i, j, testcase.Result, result)
			}
		}
	}
}

// TestParseIncludeNegative shows correct behavior of include qualifier.
// We expect all the IP addressess to fail (for tests that domain/record
// exists).  Please note that all tested IP address will match
// negative.matching.net domain, or last term (-all), hence the recursive call
// will always return (match, Fail). As per recursive calls for include term we
// are supposed to not mach top-level include term.  On the other hands, for
// include term, that refer to non existing domains we are supposed to return
// (match, Permerror)
func TestParseIncludeNegative(t *testing.T) {
	/* helper functions */

	hosts := make(map[uint16][]string)
	hosts[dns.TypeTXT] = []string{
		"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
	}
	hosts[dns.TypeMX] = []string{
		"mail.matching.net. 0 IN MX 5 mail.matching.net.",
		"mail.matching.net. 0 IN MX 10 mail2.matching.net.",
	}
	hosts[dns.TypeA] = []string{
		"postivie.matching.net. 0 IN A 172.100.100.1",
		"positive.matching.net. 0 IN A 173.18.0.2",
		"positive.matching.net. 0 IN A 173.20.20.1",
		"positive.matching.net. 0 IN A 173.20.21.1",
		"negative.matching.net. 0 IN A 172.18.100.100",
		"negative.matching.net. 0 IN A 172.18.100.101",
		"negative.matching.net. 0 IN A 172.18.100.102",
		"negative.matching.net. 0 IN A 172.18.100.103",
		"mail.matching.net.	0 IN A 173.18.0.2",
		"mail2.matching.net. 0 IN A 173.20.20.20",
	}
	includeMatchingCom := Zone(hosts)
	dns.HandleFunc("matching.net.", includeMatchingCom)
	defer dns.HandleRemove("matching.net.")

	/*******************************/
	ips := []net.IP{
		// completely random IP address out of the net segment
		{80, 81, 82, 83},
		// ip addresses from failing negative.matching.net A records
		{173, 18, 100, 100},
		{173, 18, 100, 101},
		{173, 18, 100, 102},
		{173, 18, 100, 103},
	}

	testcases := []TokenTestCase{
		{&token{mechanism: tInclude, qualifier: qMinus, value: "_spf.matching.net"}, None, false, false},
		{&token{mechanism: tInclude, qualifier: qPlus, value: "_spf.matching.net"}, None, false, false},
		// TODO(zaccone): Following 3 tests are practically identitcal
		{&token{mechanism: tInclude, qualifier: qPlus, value: "_errspf.matching.net"}, Permerror, true, false},
		{&token{mechanism: tInclude, qualifier: qPlus, value: "nospf.matching.net"}, Permerror, true, false},
		{&token{mechanism: tInclude, qualifier: qPlus, value: "idontexist.matching.net"}, Permerror, true, false},

		// empty input qualifier results in Permerror withour recursive calls
		{&token{mechanism: tInclude, qualifier: qMinus, value: ""}, Permerror, true, false},

		{&token{mechanism: tInclude, qualifier: qPlus, value: "_errspf.matching.net"}, Permerror, true, true},
	}

	var match bool
	var result Result

	for _, testcase := range testcases {
		for _, ip := range ips {
			opts := []Option{WithResolver(testResolver)}
			if testcase.ignoreMatches {
				opts = append(opts, IgnoreMatches())
			}

			p := newParser(opts...).with(stub, "matching.net", "matching.net", ip)

			p.ip = ip
			match, result, _ = p.parseInclude(testcase.Input)
			if testcase.Match != match {
				t.Error("IP:", ip, ":", testcase.Input.value, ": Match mismatch, expected ", testcase.Match, " got ", match)
			}
			if testcase.Result != result {
				t.Error("IP:", ip, ":", testcase.Input.value, ": Result mismatch, expected ", testcase.Result, " got ", result)
			}
		}
	}
}

// TestParseExists executes tests for exists term.
func TestParseExists(t *testing.T) {
	hosts := make(map[uint16][]string)
	hosts[dns.TypeA] = []string{
		"positive.matching.net. 0 IN A 172.20.20.20",
		"positive.matching.net. 0 IN A 172.18.0.1",
		"positive.matching.net. 0 IN A 172.18.0.2",
	}
	dns.HandleFunc("positive.matching.net.", Zone(hosts))
	defer dns.HandleRemove("positive.matching.net.")

	hosts = make(map[uint16][]string)
	hosts[dns.TypeA] = []string{
		"positive.matching.com. 0 IN A 172.20.20.20",
		"positive.matching.com. 0 IN A 172.18.0.1",
		"positive.matching.com. 0 IN A 172.18.0.2",
	}
	dns.HandleFunc("positive.matching.com.", Zone(hosts))
	defer dns.HandleRemove("positive.matching.com.")

	testcases := []TokenTestCase{
		{&token{mechanism: tExists, qualifier: qPlus, value: "positive.matching.net"}, Pass, true, false},
		{&token{mechanism: tExists, qualifier: qMinus, value: "positive.matching.net"}, Fail, true, false},
		{&token{mechanism: tExists, qualifier: qMinus, value: "idontexist.matching.net"}, Fail, false, false},
		{&token{mechanism: tExists, qualifier: qMinus, value: "idontexist.%{d}"}, Fail, false, false},
		{&token{mechanism: tExists, qualifier: qTilde, value: "positive.%{d}"}, Softfail, true, false},
		{&token{mechanism: tExists, qualifier: qTilde, value: "positive.%{d}"}, Softfail, true, false},
		{&token{mechanism: tExists, qualifier: qTilde, value: ""}, Permerror, true, false},
		{&token{mechanism: tExists, qualifier: qTilde, value: "invalidsyntax%{}"}, Permerror, true, false},

		{&token{mechanism: tExists, qualifier: qPlus, value: "positive.matching.net"}, Pass, true, true},
		{&token{mechanism: tExists, qualifier: qMinus, value: "positive.matching.net"}, Fail, true, true},
	}

	for _, testcase := range testcases {
		opts := []Option{WithResolver(testResolver)}
		if testcase.ignoreMatches {
			opts = append(opts, IgnoreMatches())
		}

		p := newParser(opts...).with(stub, "matching.com", "matching.com", ip)

		match, result, _, _ := p.parseExists(testcase.Input)
		if testcase.Match != match {
			t.Error("Match mismatch, expected ", testcase.Match, " got ", match)
		}
		if testcase.Result != result {
			t.Error("Result mismatch, expected ", testcase.Result, " got ", result)
		}
	}
}

type parseTestCase struct {
	Query  string
	IP     net.IP
	Result Result
}

// TestParse tests whole Parser.Parse() method
func TestParse(t *testing.T) {
	testResolverCache.Clear()

	dns.HandleFunc("matching.com.", Zone(map[uint16][]string{
		dns.TypeMX: {
			"matching.com. 0 in MX 5 matching.com.",
		},
		dns.TypeA: {
			"matching.com. 0 IN A 172.20.20.20",
			"matching.com. 0 IN A 172.18.0.1",
			"matching.com. 0 IN A 172.18.0.2",
		},
	}))
	defer dns.HandleRemove("matching.com.")

	dns.HandleFunc("matching.net.", Zone(map[uint16][]string{
		dns.TypeMX: {
			"matching.net. 0 IN MX 5 matching.net.",
		},
		dns.TypeA: {
			"matching.net. 0 IN A 173.18.0.2",
			"matching.net. 0 IN A 173.20.20.20",
		},
	}))
	defer dns.HandleRemove("matching.net.")

	dns.HandleFunc("_spf.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
		},
	}))
	defer dns.HandleRemove("_spf.matching.net.")

	dns.HandleFunc("positive.matching.net.", Zone(map[uint16][]string{
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("positive.matching.net.")

	dns.HandleFunc("negative.matching.net.", Zone(map[uint16][]string{
		dns.TypeA: {
			"negative.matching.net. 0 IN A 172.100.100.1",
			"negative.matching.net. 0 IN A 173.18.0.2",
			"negative.matching.net. 0 IN A 173.20.20.1",
			"negative.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("negative.matching.net.")

	dns.HandleFunc("lb.matching.com.", Zone(map[uint16][]string{
		dns.TypeA: {
			"lb.matching.com. 0 IN A 172.101.101.1",
		},
	}))
	defer dns.HandleRemove("lb.matching.com.")

	dns.HandleFunc("loop.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop.matching.net. 0 IN TXT "v=spf1 include:loop.matching.com -all"`,
		},
	}))
	defer dns.HandleRemove("loop.matching.net.")

	dns.HandleFunc("loop.matching.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop.matching.com. 0 IN TXT "v=spf1 include:loop.matching.net -all"`,
		},
	}))
	defer dns.HandleRemove("loop.matching.com.")

	dns.HandleFunc("loop2.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop2.matching.net. 0 IN TXT "v=spf1 redirect=loop2.matching.com"`,
		},
	}))
	defer dns.HandleRemove("loop2.matching.net.")

	dns.HandleFunc("loop2.matching.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop2.matching.com. 0 IN TXT "v=spf1 redirect=loop2.matching.net"`,
		},
	}))
	defer dns.HandleRemove("loop2.matching.com.")

	dns.HandleFunc("10.0.0.1.matching.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`10.0.0.1.matching.com. 0 IN TXT "v=spf1 +all"`,
		},
		dns.TypeA: {
			"10.0.0.1.matching.com. 0 IN A 10.0.0.1",
		},
		dns.TypeMX: {
			"10.0.0.1.matching.com. 0 in MX 5 10.0.0.1.matching.com.",
		},
	}))
	defer dns.HandleRemove("10.0.0.1.matching.com.")

	parseTestCases := []parseTestCase{
		{"v=spf1 -all", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 mx -all", net.IP{172, 20, 20, 20}, Pass},
		{"v=spf1 ?mx -all", net.IP{172, 20, 20, 20}, Neutral},
		{"v=spf1 ~mx -all", net.IP{172, 20, 20, 20}, Softfail},
		{"v=spf1 A -mx -all", net.IP{172, 18, 0, 2}, Pass},
		{"v=spf1 -mx a -all", net.IP{172, 18, 0, 2}, Fail},
		{"v=spf1 +mx:matching.net -a -all", net.IP{173, 18, 0, 2}, Pass},
		{"v=spf1 +mx:matching.net -a -all", net.IP{172, 17, 0, 2}, Fail},
		{"v=spf1 a:matching.net -all", net.IP{173, 18, 0, 2}, Pass},
		{"v=spf1 +ip4:128.14.15.16 -all", net.IP{128, 14, 15, 16}, Pass},
		{"v=spf1 ~ip6:2001:56::2 -all", net.ParseIP("2001:56::2"), Softfail},
		// Test ensures that once no term was matched and there is no
		// redirect mechanism, we should return Neutral result.
		{"v=spf1 -ip4:8.8.8.8", net.IP{9, 9, 9, 9}, Neutral},
		// Test will return SPFResult Fail as 172.20.20.1 does not result
		// positively for domain _spf.matching.net
		{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 20, 20, 1}, Fail},
		// Test will return SPFResult Pass as 172.100.100.1 is within
		// positive.matching.net A records, that are marked as +a:
		{"v=spf1 ip4:127.0.0.1 +include:_spf.matching.net -all", net.IP{172, 100, 100, 1}, Pass},
		// Test for syntax errors (include must have nonempty domain parameter)
		{"v=spf1 ip4:127.0.0.1 +include -all", net.IP{172, 100, 100, 1}, Permerror},
		{"v=spf1 ip4:127.0.0.1 ?include -all", net.IP{172, 100, 100, 1}, Permerror},
		// Include didn't match domain unexistent.com and underneath returned
		// Permerror, hence top level result is (match, Permerror) as per
		// recursive table in section 5.2 of RFC7208
		{"v=spf1 +include:unexistent.com -all", net.IP{172, 100, 100, 1}, Permerror},
		{"v=spf1 ?exists:lb.%{d} -all", ip, Neutral},
		// domain is set to matching.com, macro >>d1r<< will reverse domain to
		// >>com.matching<< and trim to first part counting from right,
		// effectively returning >>matching<<, which we later concatenate with
		// the >>.com<< suffix. This test should give same matching result as
		// the test above, as effectively the host to be queried is identical.
		{"v=spf1 ?exists:lb.%{d1r}.com -all", ip, Neutral},
		// 4.6.4 DNS Lookup Limits
		// Some mechanisms and modifiers (collectively, "terms") cause DNS
		// queries at the time of evaluation, and some do not.  The following
		// terms cause DNS queries: the "include", "a", "mx", "ptr", and
		// "exists" mechanisms, and the "redirect" modifier.  SPF
		// implementations MUST limit the total number of those terms to 10
		// during SPF evaluation, to avoid unreasonable load on the DNS.  If
		// this limit is exceeded, the implementation MUST return "permerror".
		// The other terms -- the "all", "ip4", and "ip6" mechanisms, and the
		// "exp" modifier -- do not cause DNS queries at the time of SPF
		// evaluation (the "exp" modifier only causes a lookup
		// https://tools.ietf.org/html/rfc7208#section-2.6
		{"v=spf1 include:loop.matching.com -all", net.IP{10, 0, 0, 1}, Permerror},
		{"v=spf1 redirect=loop2.matching.com", net.IP{10, 0, 0, 1}, Permerror},
		{"v=spf1 include:%{i}.matching.com -all", net.IP{10, 0, 0, 1}, Pass},
		{"v=spf1 include:" + strings.Repeat("z", 254) + ".%{i}.matching.com -all", net.IP{10, 0, 0, 1}, Pass},
		{"v=spf1 include:" + strings.Repeat("z", 254) + "%{i}.matching.com -all", net.IP{10, 0, 0, 1}, Permerror},
		{"v=spf1 redirect=%{i}.matching.com", net.IP{10, 0, 0, 1}, Pass},
		{"v=spf1 a:%{i}.matching.com/32 -all", net.IP{10, 0, 0, 1}, Pass},
		{"v=spf1 mx:%{i}.matching.com/32 -all", net.IP{10, 0, 0, 1}, Pass},
	}

	for _, testcase := range parseTestCases {
		type R struct {
			r Result
			e error
		}
		done := make(chan R)
		go func() {
			result, _, _, err := newParser(WithResolver(NewLimitedResolver(testResolver, 5, 4, 2))).with(testcase.Query, "matching.com", "matching.com", testcase.IP).check()
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

func TestCheckHost_RecursionLoop(t *testing.T) {
	testResolverCache.Clear()

	dns.HandleFunc("loop.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop.matching.net. 0 IN TXT "v=spf1 include:loop1.matching.net -all"`,
		},
	}))
	defer dns.HandleRemove("loop.matching.net.")

	dns.HandleFunc("loop1.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop1.matching.net. 0 IN TXT "v=spf1 include:loop2.matching.net -all"`,
		},
	}))
	defer dns.HandleRemove("loop1.matching.net.")

	dns.HandleFunc("loop2.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`loop2.matching.net. 0 IN TXT "v=spf1 include:loop.matching.net -all"`,
		},
	}))
	defer dns.HandleRemove("loop2.matching.net.")

	tests := []struct {
		query  string
		ip     net.IP
		result Result
		err    string
	}{
		{
			"v=spf1 include:loop.matching.net -all",
			net.IP{10, 0, 0, 1},
			Permerror,
			"infinite recursion detected [include:loop.matching.net include:loop1.matching.net include:loop2.matching.net include:loop.matching.net]",
		},
		{
			"v=spf1 redirect=loop.matching.net",
			net.IP{10, 0, 0, 1},
			Permerror,
			"infinite recursion detected [include:loop1.matching.net include:loop2.matching.net include:loop.matching.net]",
		},
	}

	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			type R struct {
				r Result
				e error
			}
			done := make(chan R)
			go func() {
				result, _, _, err := newParser(WithResolver(NewLimitedResolver(testResolver, 4, 4, 2))).with(test.query, "matching.com", "matching.com", test.ip).check()
				done <- R{result, err}
			}()
			select {
			case <-time.After(5 * time.Second):
				t.Errorf("%q failed due to timeout", test.query)
			case r := <-done:
				if r.r != Permerror && r.r != Temperror && r.e != nil {
					t.Errorf("%q Unexpected error while parsing: %s", test.query, r.e)
				}
				if r.r != test.result {
					t.Errorf("%q Expected %v, got %v", test.query, test.result, r.r)
				}
				if r.e.Error() != test.err {
					t.Errorf("%q Expected %v, got %v", test.query, test.err, r.e)
				}
			}
		})
	}
}

// TestParseRedirect tests whole parsing behavior with a special testing of
// redirect modifier
func TestHandleRedirect(t *testing.T) {
	dns.HandleFunc("matching.net.", Zone(map[uint16][]string{
		dns.TypeMX: {
			"matching.net. 0 IN MX 5 matching.net.",
		},
		dns.TypeA: {
			"matching.net. 0 IN A 173.18.0.2",
			"matching.net. 0 IN A 173.20.20.20",
		},
	}))
	defer dns.HandleRemove("matching.net.")

	dns.HandleFunc("_spf.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"_spf.matching.net. 0 IN TXT \"v=spf1 a:positive.matching.net -a:negative.matching.net ~mx -all\"",
		},
	}))
	defer dns.HandleRemove("_spf.matching.net.")

	dns.HandleFunc("nospf.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"nospf.matching.net. 0 IN TXT \"no spf here\"",
		},
	}))
	defer dns.HandleRemove("nospf.matching.net.")

	dns.HandleFunc("positive.matching.net.", Zone(map[uint16][]string{
		dns.TypeA: {
			"positive.matching.net. 0 IN A 172.100.100.1",
			"positive.matching.net. 0 IN A 173.18.0.2",
			"positive.matching.net. 0 IN A 173.20.20.1",
			"positive.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("positive.matching.net.")

	dns.HandleFunc("negative.matching.net.", Zone(map[uint16][]string{
		dns.TypeA: {
			"negative.matching.net. 0 IN A 172.100.100.1",
			"negative.matching.net. 0 IN A 173.18.0.2",
			"negative.matching.net. 0 IN A 173.20.20.1",
			"negative.matching.net. 0 IN A 173.20.21.1",
		},
	}))
	defer dns.HandleRemove("negative.matching.net.")

	dns.HandleFunc("redirect.matching.net.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"redirect.matching.net. 0 IN TXT \"v=spf1 redirect=matching.com\"",
		},
	}))
	defer dns.HandleRemove("redirect.matching.net.")

	dns.HandleFunc("redirect.matching.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"redirect.matching.com. 0 IN TXT \"v=spf1 redirect=redirect.matching.net\"",
		},
	}))
	defer dns.HandleRemove("redirect.matching.com.")

	dns.HandleFunc("matching.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"matching.com. 0 IN TXT \"v=spf1 mx:matching.com -all\"",
		},
		dns.TypeMX: {
			"matching.com.	0 IN MX 5 mail.matching.com",
		},
		dns.TypeA: {
			"mail.matching.com.	0 IN A 172.18.0.2",
		},
	}))
	defer dns.HandleRemove("matching.com.")

	ParseTestCases := []parseTestCase{
		{"v=spf1 -all redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Fail},
		{"v=spf1 redirect=_spf.matching.net -all", net.IP{172, 100, 100, 1}, Fail},
		{"v=spf1 redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Pass},
		{"v=spf1 redirect=malformed", net.IP{172, 100, 100, 1}, Permerror},
		{"v=spf1 redirect=_spf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Permerror},
		{"v=spf1 +ip4:127.0.0.1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Pass},
		{"v=spf1 -ip4:127.0.0.1 redirect=nospf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 +include:_spf.matching.net redirect=_spf.matching.net", net.IP{127, 0, 0, 1}, Fail},
		{"v=spf1 ~include:_spf.matching.net redirect=_spf.matching.net", net.IP{172, 100, 100, 1}, Softfail},
		// Ensure recursive redirects work
		{"v=spf1 redirect=redirect.matching.com", net.IP{172, 18, 0, 2}, Pass},
		{"v=spf1 redirect=redirect.matching.com", net.IP{127, 0, 0, 1}, Fail},
	}

	for _, testcase := range ParseTestCases {
		p := newParser(WithResolver(testResolver)).with(testcase.Query, "matching.com", "matching.com", testcase.IP)
		result, _, _, _ := p.check()
		if result != testcase.Result {
			t.Errorf("%q Expected %v, got %v", testcase.Query, testcase.Result, result)
		}
	}
}

type ExpTestCase struct {
	Query       string
	Explanation string
}

func TestHandleExplanation(t *testing.T) {
	// static.exp.matching.com.        IN      TXT "Invalid SPF record"
	// ip.exp.matching.com.            IN      TXT "%{i} is not one of %{d}'s designated mail servers."
	// redirect.exp.matching.com.      IN      TXT "See http://%{d}/why.html?s=%{s}&i=%{i}"

	dns.HandleFunc("static.exp.matching.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"static.exp.matching.com. 0 IN TXT \"Invalid SPF record\"",
		},
	}))
	defer dns.HandleRemove("static.exp.matching.com.")

	dns.HandleFunc("ip.exp.matching.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			"ip.exp.matching.com. 0 in TXT \"%{i} is not one of %{d}'s designated mail servers.\"",
		},
	}))
	defer dns.HandleRemove("ip.exp.matching.com.")

	expTestCases := []ExpTestCase{
		{
			"v=spf1 -all exp=static.exp.matching.com",
			"Invalid SPF record",
		},
		{
			"v=spf1 -all exp=ip.exp.matching.com",
			"127.0.0.1 is not one of matching.com's designated mail servers.",
		},
		// TODO(zaccone): Cover this testcase
		// ExpTestCase{"v=spf1 -all exp=redirect.exp.matching.com",
		// ExpT"See http://matching.com/why.html?s=&i="},
	}

	for _, testcase := range expTestCases {
		p := newParser(WithResolver(testResolver)).with(testcase.Query, "matching.com", "matching.com", ip)
		_, exp, _, err := p.check()
		if err != nil {
			t.Errorf("%q unexpected error while parsing: %s", testcase.Query, err)
		}
		if exp != testcase.Explanation {
			t.Errorf("%q explanation mismatch, expected %q, got %q", testcase.Query,
				testcase.Explanation, exp)
		}
	}
}

func TestSelectingRecord(t *testing.T) {
	dns.HandleFunc("v-spf2.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`v-spf2. 0 IN TXT "v=spf2"`,
		},
	}))
	defer dns.HandleRemove("v-spf2.")

	dns.HandleFunc("v-spf10.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`v-spf10. 0 IN TXT "v=spf10"`,
		},
	}))
	defer dns.HandleRemove("v-spf10.")

	dns.HandleFunc("no-record.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`no-record. 0 IN TXT ""`,
		},
	}))
	defer dns.HandleRemove("no-record.")

	dns.HandleFunc("many-records.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`many-records. 0 IN TXT "v=spf1"`,
			`many-records. 0 IN TXT "v=spf1"`,
			`many-records. 0 IN TXT ""`,
		},
	}))
	defer dns.HandleRemove("many-records.")

	dns.HandleFunc("mixed-records.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`mixed-records. 0 IN TXT "v=spf1 +all"`,
			`mixed-records. 0 IN TXT "v-spf10"`,
			`mixed-records. 0 IN TXT ""`,
		},
	}))
	defer dns.HandleRemove("many-records.")

	samples := []struct {
		d string
		r Result
		e error
	}{
		{"notexists", None, SpfError{kind: spferr.KindDNS, err: ErrDNSPermerror}},
		{"v-spf2", None, SpfError{kind: spferr.KindValidation, err: ErrSPFNotFound}},
		{"v-spf10", None, SpfError{kind: spferr.KindValidation, err: ErrSPFNotFound}},
		{"no-record", None, SpfError{kind: spferr.KindValidation, err: ErrSPFNotFound}},
		{"many-records", Permerror, SpfError{kind: spferr.KindValidation, err: ErrTooManySPFRecords}},
		{"mixed-records", Pass, nil},
	}

	ip := net.ParseIP("10.0.0.1")
	for i, s := range samples {
		r, _, _, e := CheckHost(ip, s.d, s.d, WithResolver(testResolver))
		if r != s.r || e != s.e {
			t.Errorf("#%d `%s` want [`%v` `%v`], got [`%v` `%v`]", i, s.d, s.r, s.e, r, e)
		}
	}
}

func TestCheckHost_Loops(t *testing.T) {
	dns.HandleFunc("example.com.", Zone(map[uint16][]string{
		dns.TypeA: {
			`example.com. 0 IN A 1.1.1.1`,
		},
		dns.TypeMX: {
			`example.com. 0 IN MX 0 1.1.1.1`,
		},
		dns.TypeTXT: {
			`example.com. 0 IN TXT "v=spf1 a mx include:a.example.com include:b.example.com include:c.example.com -all"`,
		},
	}))
	defer dns.HandleRemove("example.com.")

	dns.HandleFunc("a.example.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`a.example.com. 0 IN TXT "v=spf1 include:a.example.com -all"`,
		},
	}))
	defer dns.HandleRemove("a.example.com.")

	dns.HandleFunc("b.example.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`b.example.com. 0 IN TXT "v=spf1 include:b.example.com -all"`,
		},
	}))
	defer dns.HandleRemove("b.example.com.")

	dns.HandleFunc("c.example.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`c.example.com. 0 IN TXT "v=spf1 include:c.example.com -all"`,
		},
	}))
	defer dns.HandleRemove("c.example.com.")

	dns.HandleFunc("ab.example.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`ab.example.com. 0 IN TXT "v=spf1 include:ba.example.com -all"`,
		},
	}))
	defer dns.HandleRemove("ab.example.com.")

	dns.HandleFunc("ba.example.com.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`ba.example.com. 0 IN TXT "v=spf1 include:ab.example.com -all"`,
		},
	}))
	defer dns.HandleRemove("ba.example.com.")

	dns.HandleFunc("mail.example.com.", Zone(map[uint16][]string{}))
	defer dns.HandleRemove("mail.example.com.")

	tests := []struct {
		name string
		d    string
		r    Result
		e    error
		opts []Option
	}{
		{
			"normal mode", "ab.example.com", Permerror,
			SpfError{
				spferr.KindValidation,
				&token{mechanism: tInclude, qualifier: qPlus, value: "ba.example.com", key: "include"},
				SpfError{spferr.KindValidation, &token{mechanism: tInclude, qualifier: qPlus, value: "ab.example.com", key: "include"}, SpfError{kind: spferr.KindValidation, err: ErrLoopDetected}},
			},
			[]Option{WithResolver(testResolver)},
		},
		{"walker mode, errors below threshold", "example.com", unreliableResult, ErrUnreliableResult, []Option{WithResolver(testResolver), IgnoreMatches(), ErrorsThreshold(4)}},
		{"walker mode, errors above threshold", "example.com", unreliableResult, ErrTooManyErrors, []Option{WithResolver(testResolver), IgnoreMatches(), ErrorsThreshold(2)}},
	}

	ip := net.ParseIP("10.0.0.1")
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d-%s", i, test.name), func(t *testing.T) {
			r, _, _, e := CheckHost(ip, test.d, test.d, test.opts...)
			if diff := cmp.Diff(test.r, r); diff != "" {
				t.Errorf("CheckHost() result differs: (-want +got)\n%s", diff)
			}
			if diff := cmp.Diff(test.e, e, deepAllowUnexported(SpfError{}, token{}, errors.New(""))); diff != "" {
				t.Errorf("CheckHost() errors differs: (-want +got)\n%s", diff)
			}
		})
	}
}

func deepAllowUnexported(vs ...interface{}) cmp.Option {
	m := make(map[reflect.Type]struct{})
	for _, v := range vs {
		structTypes(reflect.ValueOf(v), m)
	}
	var typs []interface{}
	for t := range m {
		typs = append(typs, reflect.New(t).Elem().Interface())
	}
	return cmp.AllowUnexported(typs...)
}

func structTypes(v reflect.Value, m map[reflect.Type]struct{}) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			structTypes(v.Elem(), m)
		}
	case reflect.Interface:
		if !v.IsNil() {
			structTypes(v.Elem(), m)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			structTypes(v.Index(i), m)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			structTypes(v.MapIndex(k), m)
		}
	case reflect.Struct:
		m[v.Type()] = struct{}{}
		for i := 0; i < v.NumField(); i++ {
			structTypes(v.Field(i), m)
		}
	}
}
