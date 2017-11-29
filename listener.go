package spf

import (
	"net"
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