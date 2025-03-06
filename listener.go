package spf

import (
	"net"
)

// Listener interface defines callbacks for tracking SPF processing events.
//
// Implementers of this interface can monitor various stages of SPF evaluation
// including record parsing, directive processing, IP matching, and final results.
type Listener interface {
	// CheckHost is called when starting evaluation of an SPF policy for a specific IP and domain.
	CheckHost(ip net.IP, domain, sender string)
	// CheckHostResult is called when evaluation completes with the final result.
	CheckHostResult(r Result, explanation string, extras *ResponseExtras, err error)
	// SPFRecord is called when a valid SPF record is found.
	SPFRecord(s string)
	// Directive is called when processing each directive in the SPF record.
	Directive(unused bool, qualifier, mechanism, key, value, effectiveValue string)
	// NonMatch is called when a directive does not match.
	NonMatch(qualifier, mechanism, value string, result Result, err error)
	// Match is called when a directive matches.
	Match(qualifier, mechanism, value string, result Result, explanation string, extras *ResponseExtras, err error)
	// FirstMatch is called when the first matching directive is found.
	FirstMatch(r Result, err error)
	// MatchingIP is called when an IP address matches a network range.
	MatchingIP(qualifier, mechanism, value, fqdn string, ipn net.IPNet, host string, ip net.IP)
	// LookupExtras should only be called after a Directive or CheckHost call,
	// to ensure updates on correct directive and state stay consistent.
	LookupExtras(qualifier, mechanism, value, fqdn string, extras *ResponseExtras)
	// TXT is called with SPF candidate and policy strings from TXT records.
	// TXT is called only after CheckHost call
	TXT(candidates, policies []string)
}
