package spf

import (
	"fmt"
	"io"
	"net"
	"strings"
)

type Listener interface {
	CheckHost(ip net.IP, domain, sender string)
	CheckHostResult(r Result, explanation string, err error)
	SPFRecord(s string)
	Directive(qualifier, mechanism, value string)
	NonMatch(qualifier, mechanism, value string, result Result, err error)
	Match(qualifier, mechanism, value string, result Result, explanation string, err error)
	Redirect(domain string)
}

type printer struct {
	w io.Writer
	c int
}

func (p *printer) CheckHost(ip net.IP, domain, sender string) {
	if p.c != 0 {
		fmt.Fprintln(p.w)
	}
	fmt.Fprintf(p.w, "%sCHECK_HOST(%q, %q, %q)\n", strings.Repeat("  ", p.c), ip, domain, sender)
	p.c++
}

func (p *printer) SPFRecord(s string) {
	fmt.Fprintf(p.w, "%sSPF: %s\n", strings.Repeat("  ", p.c), s)
}

func (p *printer) CheckHostResult(r Result, explanation string, err error) {
	p.c--
	fmt.Fprintf(p.w, "%s= %s, %q, %v\n\n", strings.Repeat("  ", p.c), r, explanation, err)
}

func (p *printer) Directive(qualifier, mechanism, value string) {
	fmt.Fprintf(p.w, "%s", strings.Repeat("  ", p.c))
	if qualifier == "+" {
		qualifier = ""
	}
	fmt.Fprintf(p.w, "%s%s", qualifier, mechanism)
	if value != "" {
		delimiter := ":"
		if mechanism == "v" {
			delimiter = "="
		}
		fmt.Fprintf(p.w, "%s%s", delimiter, value)
	}
	fmt.Fprintln(p.w)
}

func (p *printer) NonMatch(qualifier, mechanism, value string, result Result, err error) {
	//fmt.Fprintf(p.w, "%sNON-MATCH: %s, %v\n", strings.Repeat("  ", p.c), result, err)
}

func (p *printer) Match(qualifier, mechanism, value string, result Result, explanation string, err error) {
	//fmt.Fprintf(p.w, "%sMATCH: %s, %q, %v\n", strings.Repeat("  ", p.c), result, explanation, err)
}

func (p *printer) Redirect(domain string) {
	fmt.Fprintf(p.w, "%s REDIRECT: %s\n", strings.Repeat("  ", p.c), domain)
}
