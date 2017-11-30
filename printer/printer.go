package printer

import (
	"fmt"
	"io"
	"net"
	"strings"

	"sync"

	"github.com/redsift/spf"
)

func New(w io.Writer, r spf.Resolver) *Printer {
	return &Printer{
		w: w,
		r: r,
	}
}

type Printer struct {
	sync.Mutex
	w    io.Writer
	c    int
	r    spf.Resolver
	done bool
}

func (p *Printer) CheckHost(ip net.IP, domain, sender string) {
	fmt.Fprintf(p.w, "%sCHECK_HOST(%q, %q, %q)\n", strings.Repeat("  ", p.c), ip, domain, sender)
	p.c++
}

func (p *Printer) SPFRecord(s string) {
	fmt.Fprintf(p.w, "%sSPF: %s\n", strings.Repeat("  ", p.c), s)
}

func (p *Printer) CheckHostResult(r spf.Result, explanation string, err error) {
	p.Lock()
	defer p.Unlock()
	p.c--
	p.done = p.c == 0
	fmt.Fprintf(p.w, "%s= %s, %q, %v\n", strings.Repeat("  ", p.c), r, explanation, err)
}

func (p *Printer) Directive(unused bool, qualifier, mechanism, value, effectiveValue string) {
	fmt.Fprintf(p.w, "%s", strings.Repeat("  ", p.c))
	if qualifier == "+" {
		qualifier = ""
	}
	if unused {
		fmt.Fprint(p.w, "unused ")
	}
	fmt.Fprintf(p.w, "%s%s", qualifier, mechanism)
	delimiter := ":"
	if mechanism == "v" {
		delimiter = "="
	}
	if value != "" {
		fmt.Fprintf(p.w, "%s%s", delimiter, value)
	}
	if effectiveValue != "" {
		fmt.Fprintf(p.w, " (%s)", effectiveValue)
	}
	fmt.Fprintln(p.w)
}

func (p *Printer) NonMatch(qualifier, mechanism, value string, result spf.Result, err error) {
	//fmt.Fprintf(p.w, "%sNON-MATCH: %s, %v\n", strings.Repeat("  ", p.c), result, err)
}

func (p *Printer) Match(qualifier, mechanism, value string, result spf.Result, explanation string, err error) {
	//fmt.Fprintf(p.w, "%sMATCH: %s, %q, %v\n", strings.Repeat("  ", p.c), result, explanation, err)
}

func (p *Printer) LookupTXT(name string) ([]string, error) {
	fmt.Fprintf(p.w, "%s  lookup(TXT) %s\n", strings.Repeat("  ", p.c), name)
	return p.r.LookupTXT(name)
}

func (p *Printer) LookupTXTStrict(name string) ([]string, error) {
	fmt.Fprintf(p.w, "%s  lookup(TXT:strict) %s\n", strings.Repeat("  ", p.c), name)
	return p.r.LookupTXTStrict(name)
}

func (p *Printer) Exists(name string) (bool, error) {
	fmt.Fprintf(p.w, "%s  lookup(A)\n", strings.Repeat("  ", p.c))
	return p.r.Exists(name)
}

func (p *Printer) MatchIP(name string, matcher spf.IPMatcherFunc) (bool, error) {
	return p.r.MatchIP(name, func(ip net.IP, fqdn string) (bool, error) {
		p.Lock()
		defer p.Unlock()
		if p.done {
			return false, nil
		}
		r, e := matcher(ip, fqdn)
		fmt.Fprintf(p.w, "%s  lookup(A,AAAA:%s) %s -> %s %t %v\n", strings.Repeat("  ", p.c), name, fqdn, ip, r, e)
		return r, e
	})
}

func (p *Printer) MatchMX(name string, matcher spf.IPMatcherFunc) (bool, error) {
	return p.r.MatchMX(name, func(ip net.IP, fqdn string) (bool, error) {
		p.Lock()
		defer p.Unlock()
		if p.done {
			return false, nil
		}
		r, e := matcher(ip, fqdn)
		fmt.Fprintf(p.w, "%s  lookup(MX:%s) %s -> %s %t %v\n", strings.Repeat("  ", p.c), name, fqdn, ip, r, e)
		return r, e
	})
}
