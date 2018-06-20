package spf

import (
	"fmt"
	"net"
	"strings"
)

// Trace holds data for "Received-SPF" header field
// https://tools.ietf.org/html/rfc7208#section-9.1
type Trace struct {
	Result       Result `json:"result"`                 // the result
	Explanation  string `json:"exp,omitempty"`          // supporting information for the result
	ClientIP     net.IP `json:"clientIp,omitempty"`     // the IP address of the SMTP client
	Identity     string `json:"identity,omitempty"`     // the identity that was checked
	Helo         string `json:"helo,omitempty"`         // the host name given in the HELO or EHLO command
	EnvelopeFrom string `json:"envelopeFrom,omitempty"` // the envelope sender mailbox
	Problem      error  `json:"problem,omitempty"`      // if an error was returned, details about the error
	Receiver     string `json:"receiver,omitempty"`     // the host name of the SPF verifier
	Mechanism    string `json:"mechanism,omitempty"`    // the mechanism that matched
}

func (r *Trace) ReceivedSPF() string {
	// TODO (dmotylev) Should resulting string be wrapped/trimmed? https://tools.ietf.org/html/rfc5322#section-2.1.1
	if r == nil {
		return ""
	}
	var b strings.Builder

	writeExp := func(s string) {
		b.WriteString(" (")
		if s != "" {
			b.WriteString(r.Explanation)
		} else {
			// https://tools.ietf.org/html/rfc7208#section-9.1
			// Received-SPF: pass (mybox.example.org: domain of
			//    myname@example.com designates 192.0.2.1 as permitted sender)
			//       receiver=mybox.example.org; client-ip=192.0.2.1;
			//       envelope-from="myname@example.com"; helo=foo.example.com;
			//
			//   Received-SPF: fail (mybox.example.org: domain of
			//                     myname@example.com does not designate
			//                     192.0.2.1 as permitted sender)
			//                     identity=mailfrom; client-ip=192.0.2.1;
			//                     envelope-from="myname@example.com";
			//
			//
			// Pass			The SPF record designates the host to be allowed to send
			// Fail			The SPF record has designated the host as NOT being allowed to send
			// SoftFail		The SPF record has designated the host as NOT being allowed to send but is in transition
			// Neutral		The SPF record specifies explicitly that nothing can be said about validity
			// None			The domain does not have an SPF record or the SPF record does not evaluate to a result
			// PermError	A permanent error has occured (eg. badly formatted SPF record)
			// TempError	A transient error has occured
			if r.Receiver != "" {
				b.WriteString(r.Receiver)
				b.WriteString(": ")
			}
			sender := "sender"
			if r.EnvelopeFrom != "" {
				sender = r.EnvelopeFrom
			}
			host := "the host"
			if r.ClientIP != nil {
				host = r.ClientIP.String()
			}
			switch r.Result {
			case Pass:
				fmt.Fprintf(&b, "domain of %s designates %s as permitted sender", sender, host)
			case Fail:
				fmt.Fprintf(&b, "domain of %s does not designate %s as permitted sender", sender, host)
			case Softfail:
				fmt.Fprintf(&b, "domain of %s does not designate %s as permitted sender but is in transition", sender, host)
			case Neutral:
				b.WriteString("nothing can be said about validity")
			case None:
				fmt.Fprintf(&b, "domain of %s does not have an SPF record or the SPF record does not evaluate to a result", sender)
			case Permerror:
				b.WriteString("a permanent error has occured")
			case Temperror:
				b.WriteString("a transient error has occured")
			}
		}
		b.WriteByte(')')
	}

	writeKV := func(sep bool, k, v string) bool {
		if v == "" {
			return sep
		}
		if sep {
			b.WriteByte(';')
		}
		b.WriteByte(' ')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		return true
	}

	b.WriteString(r.Result.String())
	writeExp(r.Explanation)
	var scol bool
	if r.ClientIP != nil {
		scol = writeKV(scol, "client-ip", r.ClientIP.String())
	}
	if r.Problem != nil {
		scol = writeKV(scol, "problem", r.Problem.Error())
	}
	scol = writeKV(scol, "identity", r.Identity)
	scol = writeKV(scol, "helo", r.Helo)
	scol = writeKV(scol, "envelope-from", r.EnvelopeFrom)
	scol = writeKV(scol, "receiver", r.Receiver)
	scol = writeKV(scol, "mechanism", r.Mechanism)
	return b.String()
}
