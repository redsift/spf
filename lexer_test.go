package spf

import (
	"reflect"
	"testing"
)

func TestLexerNext(t *testing.T) {
	spfRecord := "a:127.0.0.1"
	l := &lexer{0, 0, 0, len(spfRecord), spfRecord}

	for i, char := range spfRecord {
		if i != l.pos {
			t.Error("At position ", i, " lexer.pos is ", l.pos)
		}
		lexChar, _ := l.next()
		if char != lexChar {
			t.Error("Expected character ", char, " got ", lexChar)
		}
	}

	if !l.eof() {
		t.Error("Expected lexer to indicate EOF (didn't happen).")
	}
	if l.start != 0 {
		t.Error("For record ", spfRecord, " lexer.start should be equal to 0")
	}
}

func TestLexerScanIdent(t *testing.T) {
	tests := []struct {
		query string
		want  *token
	}{
		{"v=spf1", &token{mechanism: tVersion, qualifier: qPlus, value: "spf1", key: "v"}},
		{"v=spf1 ", &token{mechanism: tVersion, qualifier: qPlus, value: "spf1", key: "v"}},
		{"A:127.0.0.1", &token{mechanism: tA, qualifier: qPlus, value: "127.0.0.1", key: "A"}},
		{"a:127.0.0.1", &token{mechanism: tA, qualifier: qPlus, value: "127.0.0.1", key: "a"}},
		{"a", &token{mechanism: tA, qualifier: qPlus, value: ""}},
		{"A", &token{mechanism: tA, qualifier: qPlus, value: ""}},
		{"a:127.0.0.1 ", &token{mechanism: tA, qualifier: qPlus, value: "127.0.0.1", key: "a"}},
		{"?a:127.0.0.1   ", &token{mechanism: tA, qualifier: qQuestionMark, value: "127.0.0.1", key: "a"}},
		{"?ip6:2001::43   ", &token{mechanism: tIP6, qualifier: qQuestionMark, value: "2001::43", key: "ip6"}},
		{"+ip6:::1", &token{mechanism: tIP6, qualifier: qPlus, value: "::1", key: "ip6"}},
		{"^ip6:2001::4", &token{mechanism: tErr, qualifier: qErr, value: "^ip6:2001::4", key: "^ip6"}},
		{"-all", &token{mechanism: tAll, qualifier: qMinus, value: ""}},
		{"-all ", &token{mechanism: tAll, qualifier: qMinus, value: ""}},
		{"-mx:localhost", &token{mechanism: tMX, qualifier: qMinus, value: "localhost", key: "mx"}},
		{"mx", &token{mechanism: tMX, qualifier: qPlus, value: ""}},
		{"a:", &token{mechanism: tErr, qualifier: qErr, value: "a:", key: "a"}},
		{"?mx:localhost", &token{mechanism: tMX, qualifier: qQuestionMark, value: "localhost", key: "mx"}},
		{"?random:localhost", &token{mechanism: tErr, qualifier: qErr, value: "?random:localhost", key: "random"}},
		{"-:localhost", &token{mechanism: tErr, qualifier: qErr, value: "-:localhost"}},
		{"", &token{mechanism: tErr, qualifier: qErr, value: ""}},
		{"qowie", &token{mechanism: tErr, qualifier: qErr, value: "qowie"}},
		{"~+all", &token{mechanism: tErr, qualifier: qErr, value: "~+all"}},
		{"-~all", &token{mechanism: tErr, qualifier: qErr, value: "-~all"}},
		{"mx", &token{mechanism: tMX, qualifier: qPlus, value: ""}},
		{"mx/24", &token{mechanism: tMX, qualifier: qPlus, value: "/24", key: "mx"}},
		{"~mx/24", &token{mechanism: tMX, qualifier: qTilde, value: "/24", key: "mx"}},
		{"a", &token{mechanism: tA, qualifier: qPlus, value: ""}},
		{"a/24", &token{mechanism: tA, qualifier: qPlus, value: "/24", key: "a"}},
		{"~a/24", &token{mechanism: tA, qualifier: qTilde, value: "/24", key: "a"}},
		{"xss=<script>alert('SPF-XSS')</script>", &token{mechanism: tUnknownModifier, qualifier: qPlus, value: "<script>alert('SPF-XSS')</script>", key: "xss"}},
	}

	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			l := &lexer{0, len(test.query), len(test.query) - 1, len(test.query), test.query}
			got := l.scanIdent()
			if !reflect.DeepEqual(test.want, got) {
				t.Errorf("want %#v, got %#v", test.want, got)
			}
		})
	}
}

func TestIsValidName(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"John", true},
		{"john.doe", true},
		{"john-doe_123", true},
		{"123john", false},
		{".john", false},
		{"", false},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			actual := reNameRFC7208.MatchString(test.input)
			if actual != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, actual)
			}
		})
	}
}

func TestIsValidMacroString(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"%{s}", true},
		{"Hello", true},
		{"%{d10r.}", true},
		{"%%", true},
		{"%_", true},
		{"%-", true},
		{"%", false},
		{"", true},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			actual := reMacroStringRFC7208.MatchString(test.input)
			if actual != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, actual)
			}
		})
	}
}

func TestLexFunc(t *testing.T) {
	type TestPair struct {
		Record string
		Tokens []*token
	}
	versionToken := &token{mechanism: tVersion, qualifier: qPlus, value: "spf1", key: "v"}

	testpairs := []TestPair{
		{
			"v=spf1 a:127.0.0.1",
			[]*token{
				versionToken,
				{mechanism: tA, qualifier: qPlus, value: "127.0.0.1", key: "a"},
			},
		},
		{
			"v=spf1 ip4:127.0.0.1 -all",
			[]*token{
				versionToken,
				{mechanism: tIP4, qualifier: qPlus, value: "127.0.0.1", key: "ip4"},
				{mechanism: tAll, qualifier: qMinus, value: ""},
			},
		},
		{
			"v=spf1  -ptr:arpa.1.0.0.127   -all  ",
			[]*token{
				versionToken,
				{mechanism: tPTR, qualifier: qMinus, value: "arpa.1.0.0.127", key: "ptr"},
				{mechanism: tAll, qualifier: qMinus, value: "", key: ""},
			},
		},
		{
			"v=spf1  ~ip6:2001:db8::cd30 ?all  ",
			[]*token{
				versionToken,
				{mechanism: tIP6, qualifier: qTilde, value: "2001:db8::cd30", key: "ip6"},
				{mechanism: tAll, qualifier: qQuestionMark, value: ""},
			},
		},
		{
			"v=spf1  include:example.org -all  ",
			[]*token{
				versionToken,
				{mechanism: tInclude, qualifier: qPlus, value: "example.org", key: "include"},
				{mechanism: tAll, qualifier: qMinus, value: ""},
			},
		},
		{
			"v=spf1  include=example.org -all  ",
			[]*token{
				versionToken,
				{mechanism: tUnknownModifier, qualifier: qPlus, value: "example.org", key: "include"},
				{mechanism: tAll, qualifier: qMinus, value: ""},
			},
		},
		{
			"v=spf1  exists:%{ir}.%{l1r+-}._spf.%{d} +all",
			[]*token{
				versionToken,
				{mechanism: tExists, qualifier: qPlus, value: "%{ir}.%{l1r+-}._spf.%{d}", key: "exists"},
				{mechanism: tAll, qualifier: qPlus, value: ""},
			},
		},
		{
			"v=spf1  redirect=_spf.example.org",
			[]*token{
				versionToken,
				{mechanism: tRedirect, qualifier: qPlus, value: "_spf.example.org", key: "redirect"},
			},
		},
		{
			"v=spf1 mx -all exp=explain._spf.%{d}",
			[]*token{
				versionToken,
				{mechanism: tMX, qualifier: qPlus, value: ""},
				{mechanism: tAll, qualifier: qMinus, value: ""},
				{mechanism: tExp, qualifier: qPlus, value: "explain._spf.%{d}", key: "exp"},
			},
		},
	}

	for _, testpair := range testpairs {
		ltok := lex(testpair.Record)
		if !reflect.DeepEqual(testpair.Tokens, ltok) {
			t.Error("Expected tokens ", testpair.Tokens, " got ", ltok)
		}
	}
}
