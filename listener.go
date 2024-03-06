package spf

import (
	"net"
)

type Listener interface {
	CheckHost(ip net.IP, domain, sender string)
	CheckHostResult(r Result, explanation string, extras *ResponseExtras, err error)
	SPFRecord(s string)
	Directive(unused bool, qualifier, mechanism, key, value, effectiveValue string)
	NonMatch(qualifier, mechanism, value string, result Result, err error)
	Match(qualifier, mechanism, value string, result Result, explanation string, extras *ResponseExtras, err error)
	FirstMatch(r Result, err error)
	MatchingIP(qualifier, mechanism, value, fqdn string, ipn net.IPNet, host string, ip net.IP)
	// LookupExtras should only be called after a Directive or CheckHost call,
	// to ensure updates on correct directive and state stay consistent.
	LookupExtras(qualifier, mechanism, value, fqdn string, extras *ResponseExtras)
}
