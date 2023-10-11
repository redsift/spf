package printer

import (
	"fmt"
	"github.com/redsift/spf/v2"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	lc   int64
	r    spf.Resolver
	done bool
}

func (p *Printer) LookupsCount() int {
	// we deduct 1 for the very first lookup for root SPF policy
	return int(p.lc) - 1
}

func (p *Printer) CheckHost(ip net.IP, domain, sender string) {
	fmt.Fprintf(p.w, "%sCHECK_HOST(%q, %q, %q)\n", strings.Repeat("  ", p.c), ip, domain, sender)
	p.c++
}

func (p *Printer) SPFRecord(s string) {
	fmt.Fprintf(p.w, "%sSPF: %s\n", strings.Repeat("  ", p.c), s)
}

func (p *Printer) CheckHostResult(r spf.Result, explanation string, extras *spf.ResponseExtras, err error) {
	p.Lock()
	defer p.Unlock()
	p.c--
	p.done = p.c == 0
	fmt.Fprintf(p.w, "%s= %s, %v, %v, %v\n", strings.Repeat("  ", p.c), r, extras, explanation, err)
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
	// fmt.Fprintf(p.w, "%sNON-MATCH: %s, %v\n", strings.Repeat("  ", p.c), result, err)
}

func (p *Printer) Match(qualifier, mechanism, value string, result spf.Result, explanation string, extras *spf.ResponseExtras, err error) {
	// fmt.Fprintf(p.w, "%sMATCH: %s, %q, %v\n", strings.Repeat("  ", p.c), result, explanation, err)
}

func (p *Printer) VoidLookup(qualifier, mechanism, value string, fqdn string) {
	// do nothing
	fmt.Fprintf(p.w, "%sVOID: %s\n", strings.Repeat("  ", p.c), fqdn)
}

func (p *Printer) FirstMatch(r spf.Result, err error) {
	fmt.Fprintf(p.w, "%sFIRST-MATCH: %s, %v\n", strings.Repeat("  ", p.c), r, err)
}

func (p *Printer) LookupTXT(name string) ([]string, *spf.ResponseExtras, error) {
	fmt.Fprintf(p.w, "%s  lookup(TXT) %s\n", strings.Repeat("  ", p.c), name)
	atomic.AddInt64(&p.lc, 1)
	p.lc++
	return p.r.LookupTXT(name)
}

func (p *Printer) LookupTXTStrict(name string) ([]string, *spf.ResponseExtras, error) {
	fmt.Fprintf(p.w, "%s  lookup(TXT:strict) %s\n", strings.Repeat("  ", p.c), name)
	atomic.AddInt64(&p.lc, 1)
	return p.r.LookupTXTStrict(name)
}

func (p *Printer) LookupPTR(name string) ([]string, *spf.ResponseExtras, error) {
	fmt.Fprintf(p.w, "%s  lookup(PTR) %s\n", strings.Repeat("  ", p.c), name)
	atomic.AddInt64(&p.lc, 1)
	p.lc++
	return p.r.LookupPTR(name)
}

func (p *Printer) Exists(name string) (bool, *spf.ResponseExtras, error) {
	fmt.Fprintf(p.w, "%s  lookup(A)\n", strings.Repeat("  ", p.c))
	atomic.AddInt64(&p.lc, 1)
	return p.r.Exists(name)
}

func (p *Printer) MatchingIP(_, mechanism, _ string, fqdn string, ipn net.IPNet, host string, ip net.IP) {
	p.Lock()
	defer p.Unlock()
	atomic.AddInt64(&p.lc, 1)
	if p.done {
		return
	}
	n, _ := ipn.Mask.Size()
	fmt.Fprintf(p.w, "%s  lookup(%s:%s) %s -> (%s/%d has? %s) = %t\n", strings.Repeat("  ", p.c), mechanism, fqdn, host, ipn.IP, n, ip, ipn.Contains(ip))
}

func (p *Printer) MatchIP(name string, matcher spf.IPMatcherFunc) (bool, *spf.ResponseExtras, error) {
	return p.r.MatchIP(name, matcher)
}

func (p *Printer) MatchMX(name string, matcher spf.IPMatcherFunc) (bool, *spf.ResponseExtras, error) {
	return p.r.MatchMX(name, matcher)
}
