package spf

import (
	"reflect"
	"testing"
)

type LexerTest struct {
	input  string
	tokens []*token
}

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
		{"v=spf1", &token{tVersion, qPlus, "spf1"}},
		{"v=spf1 ", &token{tVersion, qPlus, "spf1"}},
		{"A:127.0.0.1", &token{tA, qPlus, "127.0.0.1"}},
		{"a:127.0.0.1", &token{tA, qPlus, "127.0.0.1"}},
		{"a", &token{tA, qPlus, ""}},
		{"A", &token{tA, qPlus, ""}},
		{"a:127.0.0.1 ", &token{tA, qPlus, "127.0.0.1"}},
		{"?a:127.0.0.1   ", &token{tA, qQuestionMark, "127.0.0.1"}},
		{"?ip6:2001::43   ", &token{tIP6, qQuestionMark, "2001::43"}},
		{"+ip6:::1", &token{tIP6, qPlus, "::1"}},
		{"^ip6:2001::4", &token{tErr, qErr, "^ip6:2001::4"}},
		{"-all", &token{tAll, qMinus, ""}},
		{"-all ", &token{tAll, qMinus, ""}},
		{"-mx:localhost", &token{tMX, qMinus, "localhost"}},
		{"mx", &token{tMX, qPlus, ""}},
		{"a:", &token{tErr, qErr, "a:"}},
		{"?mx:localhost", &token{tMX, qQuestionMark, "localhost"}},
		{"?random:localhost", &token{tErr, qErr, "?random:localhost"}},
		{"-:localhost", &token{tErr, qErr, "-:localhost"}},
		{"", &token{tErr, qErr, ""}},
		{"qowie", &token{tErr, qErr, "qowie"}},
		{"~+all", &token{tErr, qErr, "~+all"}},
		{"-~all", &token{tErr, qErr, "-~all"}},
		{"mx", &token{tMX, qPlus, ""}},
		{"mx/24", &token{tMX, qPlus, "/24"}},
		{"~mx/24", &token{tMX, qTilde, "/24"}},
		{"a", &token{tA, qPlus, ""}},
		{"a/24", &token{tA, qPlus, "/24"}},
		{"~a/24", &token{tA, qTilde, "/24"}},
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

func TestLexFunc(t *testing.T) {
	type TestPair struct {
		Record string
		Tokens []*token
	}
	versionToken := &token{tVersion, qPlus, "spf1"}

	testpairs := []TestPair{
		{"v=spf1 a:127.0.0.1",
			[]*token{
				versionToken,
				{tA, qPlus, "127.0.0.1"}}},
		{"v=spf1 ip4:127.0.0.1 -all",
			[]*token{
				versionToken,
				{tIP4, qPlus, "127.0.0.1"},
				{tAll, qMinus, ""}}},
		{"v=spf1  -ptr:arpa.1.0.0.127   -all  ",
			[]*token{
				versionToken,
				{tPTR, qMinus, "arpa.1.0.0.127"},
				{tAll, qMinus, ""}}},
		{"v=spf1  ~ip6:2001:db8::cd30 ?all  ",
			[]*token{
				versionToken,
				{tIP6, qTilde, "2001:db8::cd30"},
				{tAll, qQuestionMark, ""}}},
		{"v=spf1  include:example.org -all  ",
			[]*token{
				versionToken,
				{tInclude, qPlus, "example.org"},
				{tAll, qMinus, ""}}},
		{"v=spf1  include=example.org -all  ",
			[]*token{
				versionToken,
				{tErr, qErr, "include=example.org"},
				{tAll, qMinus, ""}}},
		{"v=spf1  exists:%{ir}.%{l1r+-}._spf.%{d} +all",
			[]*token{
				versionToken,
				{tExists, qPlus, "%{ir}.%{l1r+-}._spf.%{d}"},
				{tAll, qPlus, ""}}},
		{"v=spf1  redirect=_spf.example.org",
			[]*token{
				versionToken,
				{tRedirect, qPlus, "_spf.example.org"}}},
		{"v=spf1 mx -all exp=explain._spf.%{d}",
			[]*token{
				versionToken,
				{tMX, qPlus, ""},
				{tAll, qMinus, ""},
				{tExp, qPlus, "explain._spf.%{d}"}}},
	}

	for _, testpair := range testpairs {
		ltok := lex(testpair.Record)
		if !reflect.DeepEqual(testpair.Tokens, ltok) {
			t.Error("Expected tokens ", testpair.Tokens, " got ", ltok)
		}
	}

}
