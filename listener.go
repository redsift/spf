package spf

import (
	"net"
)

type Listener interface {
	CheckHost(ip net.IP, domain, sender string)
	CheckHostResult(r Result, explanation string, extras *ResponseExtras, err error)
	SPFRecord(s string)
	Directive(unused bool, qualifier, mechanism, value, effectiveValue string)
	NonMatch(qualifier, mechanism, value string, result Result, err error)
	Match(qualifier, mechanism, value string, result Result, explanation string, extras *ResponseExtras, err error)
	MatchingIP(qualifier, mechanism, value string, fqdn string, ipn net.IPNet, host string, ip net.IP)
	// FireVoidLookup Should only be called after a Directive or CheckHost call, to ensure count is updated to correct
	// directive and state is correct
	FireVoidLookup(token *Token, fqdn string)
}
