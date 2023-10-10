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
		{"v=spf1", &token{mechanism: tVersion, qualifier: qPlus, value: "spf1"}},
		{"v=spf1 ", &token{mechanism: tVersion, qualifier: qPlus, value: "spf1"}},
		{"A:127.0.0.1", &token{mechanism: tA, qualifier: qPlus, value: "127.0.0.1"}},
		{"a:127.0.0.1", &token{mechanism: tA, qualifier: qPlus, value: "127.0.0.1"}},
		{"a", &token{mechanism: tA, qualifier: qPlus, value: ""}},
		{"A", &token{mechanism: tA, qualifier: qPlus, value: ""}},
		{"a:127.0.0.1 ", &token{mechanism: tA, qualifier: qPlus, value: "127.0.0.1"}},
		{"?a:127.0.0.1   ", &token{mechanism: tA, qualifier: qQuestionMark, value: "127.0.0.1"}},
		{"?ip6:2001::43   ", &token{mechanism: tIP6, qualifier: qQuestionMark, value: "2001::43"}},
		{"+ip6:::1", &token{mechanism: tIP6, qualifier: qPlus, value: "::1"}},
		{"^ip6:2001::4", &token{mechanism: tErr, qualifier: qErr, value: "^ip6:2001::4"}},
		{"-all", &token{mechanism: tAll, qualifier: qMinus, value: ""}},
		{"-all ", &token{mechanism: tAll, qualifier: qMinus, value: ""}},
		{"-mx:localhost", &token{mechanism: tMX, qualifier: qMinus, value: "localhost"}},
		{"mx", &token{mechanism: tMX, qualifier: qPlus, value: ""}},
		{"a:", &token{mechanism: tErr, qualifier: qErr, value: "a:"}},
		{"?mx:localhost", &token{mechanism: tMX, qualifier: qQuestionMark, value: "localhost"}},
		{"?random:localhost", &token{mechanism: tErr, qualifier: qErr, value: "?random:localhost"}},
		{"-:localhost", &token{mechanism: tErr, qualifier: qErr, value: "-:localhost"}},
		{"", &token{mechanism: tErr, qualifier: qErr, value: ""}},
		{"qowie", &token{mechanism: tErr, qualifier: qErr, value: "qowie"}},
		{"~+all", &token{mechanism: tErr, qualifier: qErr, value: "~+all"}},
		{"-~all", &token{mechanism: tErr, qualifier: qErr, value: "-~all"}},
		{"mx", &token{mechanism: tMX, qualifier: qPlus, value: ""}},
		{"mx/24", &token{mechanism: tMX, qualifier: qPlus, value: "/24"}},
		{"~mx/24", &token{mechanism: tMX, qualifier: qTilde, value: "/24"}},
		{"a", &token{mechanism: tA, qualifier: qPlus, value: ""}},
		{"a/24", &token{mechanism: tA, qualifier: qPlus, value: "/24"}},
		{"~a/24", &token{mechanism: tA, qualifier: qTilde, value: "/24"}},
		{"xss=<script>alert('SPF-XSS')</script>", &token{mechanism: tUnknownModifier, qualifier: qPlus, value: "<script>alert('SPF-XSS')</script>"}},
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
	versionToken := &token{mechanism: tVersion, qualifier: qPlus, value: "spf1"}

	testpairs := []TestPair{
		{
			"v=spf1 a:127.0.0.1",
			[]*token{
				versionToken,
				{tA, qPlus, "127.0.0.1"},
			},
		},
		{
			"v=spf1 ip4:127.0.0.1 -all",
			[]*token{
				versionToken,
				{tIP4, qPlus, "127.0.0.1"},
				{tAll, qMinus, ""},
			},
		},
		{
			"v=spf1  -ptr:arpa.1.0.0.127   -all  ",
			[]*token{
				versionToken,
				{tPTR, qMinus, "arpa.1.0.0.127"},
				{tAll, qMinus, ""},
			},
		},
		{
			"v=spf1  ~ip6:2001:db8::cd30 ?all  ",
			[]*token{
				versionToken,
				{tIP6, qTilde, "2001:db8::cd30"},
				{tAll, qQuestionMark, ""},
			},
		},
		{
			"v=spf1  include:example.org -all  ",
			[]*token{
				versionToken,
				{tInclude, qPlus, "example.org"},
				{tAll, qMinus, ""},
			},
		},
		{
			"v=spf1  include=example.org -all  ",
			[]*token{
				versionToken,
				{tErr, qErr, "include=example.org"},
				{tAll, qMinus, ""},
			},
		},
		{
			"v=spf1  exists:%{ir}.%{l1r+-}._spf.%{d} +all",
			[]*token{
				versionToken,
				{tExists, qPlus, "%{ir}.%{l1r+-}._spf.%{d}"},
				{tAll, qPlus, ""},
			},
		},
		{
			"v=spf1  redirect=_spf.example.org",
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.org"},
			},
		},
		{
			"v=spf1 mx -all exp=explain._spf.%{d}",
			[]*token{
				versionToken,
				{tMX, qPlus, ""},
				{tAll, qMinus, ""},
				{tExp, qPlus, "explain._spf.%{d}"},
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
