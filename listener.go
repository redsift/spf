package spf

import (
	"net"
	"time"
)

type Listener interface {
	CheckHost(ip net.IP, domain, sender string)
	CheckHostResult(r Result, explanation string, ttl time.Duration, err error)
	SPFRecord(s string)
	Directive(unused bool, qualifier, mechanism, value, effectiveValue string)
	NonMatch(qualifier, mechanism, value string, result Result, err error)
	Match(qualifier, mechanism, value string, result Result, explanation string, ttl time.Duration, err error)
	FirstMatch(r Result, err error)
	MatchingIP(qualifier, mechanism, value string, fqdn string, ipn net.IPNet, host string, ip net.IP)
}
