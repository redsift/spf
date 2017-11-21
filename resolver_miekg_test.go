package spf

import (
	"testing"

	"time"

	"github.com/miekg/dns"
)

func TestMiekgDNSResolver(t *testing.T) {
	_, e := NewMiekgDNSResolver("8.8.8.8") // invalid TCP address, no port specified
	if e == nil {
		t.Errorf(`want "address 8.8.8.8: missing port in address"`)
	}
}

func TestMiekgDNSResolver_LookupTXTStrict_Multiline(t *testing.T) {
	dns.HandleFunc("multiline.test.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 0 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))
	defer dns.HandleRemove("multiline.test.")

	r, e := testResolver.LookupTXTStrict("multiline.test.")

	if e != nil {
		t.Fatal(e)
	}

	if len(r) != 1 {
		t.Errorf("want 1 got %d", len(r))
	}
}

func TestMiekgDNSResolver_Exists_Cached(t *testing.T) {
	latency := 500 * time.Millisecond
	dns.HandleFunc("slow.test.", withLatency(zone(map[uint16][]string{
		dns.TypeA: {
			`slow.test. 2 IN A 127.0.0.1`,
		},
	}), latency))
	defer dns.HandleRemove("slow.test.")

	start := time.Now()
	found, e := testResolver.Exists("slow.test.")
	d := time.Since(start)

	if !found {
		t.Error("unexpected response: want=true, got=false")
	}

	if e != nil {
		t.Fatal(e)
	}

	if d < latency {
		t.Errorf("unexpected quick response: want=%v, got=%v", latency, d)
	}

	start = time.Now()
	_, e = testResolver.Exists("slow.test.")
	d = time.Since(start)

	if e != nil {
		t.Fatal(e)
	}

	if d > latency {
		t.Errorf("too slow response for cached response: want < %v, got=%v", latency, d)
	}

	time.Sleep(2 * time.Second)
	start = time.Now()
	_, e = testResolver.Exists("slow.test.")
	d = time.Since(start)

	if d < latency {
		t.Errorf("quick response for expired cache: want=%v, got=%v", latency, d)
	}
}

func TestMiekgDNSResolver_LookupTXT_Multiline(t *testing.T) {
	dns.HandleFunc("multiline.test.", zone(map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 0 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))
	defer dns.HandleRemove("multiline.test.")

	r, e := testResolver.LookupTXT("multiline.test.")

	if e != nil {
		t.Fatal(e)
	}

	if len(r) != 1 {
		t.Errorf("want 1 got %d", len(r))
	}
}
