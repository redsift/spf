package testing

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"sync"
	"time"
)

func StartDNSServer(network string, laddr string) (*dns.Server, error) {
	pc, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Second, WriteTimeout: time.Second}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		_ = server.ActivateAndServe()
		_ = pc.Close()
	}()

	waitLock.Lock()
	return server, nil
}

func RootZone(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	switch req.Question[0].Name {
	case ".":
		m.SetReply(req)
		rr, _ := dns.NewRR(". 0 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2016110600 1800 900 604800 86400")
		m.Ns = []dns.RR{rr}
	default:
		m.SetRcode(req, dns.RcodeNameError)
	}
	_ = w.WriteMsg(m)
}

func WithDelay(f func(dns.ResponseWriter, *dns.Msg), d time.Duration) func(dns.ResponseWriter, *dns.Msg) {
	return func(writer dns.ResponseWriter, msg *dns.Msg) {
		time.Sleep(d)
		f(writer, msg)
	}
}

func Zone(zone map[uint16][]string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		rr, ok := zone[req.Question[0].Qtype]
		if !ok {
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = make([]dns.RR, 0, len(rr))
		for _, r := range rr {
			if !strings.HasPrefix(r, req.Question[0].Name) {
				continue
			}
			a, err := dns.NewRR(r)
			if err != nil {
				fmt.Printf("unable to prepare dns response: %s\n", err)
				continue
			}
			m.Answer = append(m.Answer, a)
		}
		_ = w.WriteMsg(m)
	}
}
