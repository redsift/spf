package spf

import (
	"log"
	"testing"

	"time"

	"net"

	"os"

	"github.com/bluele/gcache"
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

func TestMiekgDNSResolver_CaseProd2(t *testing.T) {
	dnsCache := gcache.New(10).LRU().Build()
	client := new(dns.Client)
	client.Timeout = 800 * time.Millisecond
	var l []Resolver
	for _, a := range []string{"8.8.8.8:53", "8.8.4.4:53"} {
		r, err := NewMiekgDNSResolver(a, MiekgDNSClient(client), MiekgDNSCache(dnsCache))
		if err != nil {
			t.Fatalf("error creating resolver: %s", err)
		}
		l = append(l, r)
	}
	r := NewRetryResolver(l, BackoffFactor(1.2))

	//p := &printer{w: os.Stdout}

	// 172.217.31.1 is an address from _netblocks3.google.com., so checking it should unfold _spf.google.com
	res, s, err := CheckHost(net.ParseIP("172.217.31.1"), "google.com", "alt4.aspmx.l.google.com",
		WithResolver(r),
		//WithListener(p),
	)
	if err != nil {
		t.Fatal(res, s, err)
	}

	if len(dnsCache.GetALL()) != 5 {
		// google.com.
		// _spf.google.com.
		// _netblocks.google.com.
		// _netblocks2.google.com.
		// _netblocks3.google.com.
		for k, v := range dnsCache.GetALL() {
			t.Logf("k=%q, v=%q", k, v.(*dns.Msg).Answer)
		}
		t.Fatal("not all requests cached")
	}
}

func TestMiekgDNSResolver_CaseProd1(t *testing.T) {
	client := new(dns.Client)
	resolver, err := NewMiekgDNSResolver("8.8.8.8:53", MiekgDNSClient(client))
	if err != nil {
		t.Fatal("Could not create resolver", err)
	}

	txts, err := resolver.LookupTXTStrict("thomsonreuters.com.")
	if err != nil {
		t.Fatal("Could not query TXTs", err)
	}

	if len(txts) == 0 {
		t.Error("No TXT records", txts)
	}
}

func ExampleWithListener() {
	r, err := NewMiekgDNSResolver("8.8.8.8:53")
	if err != nil {
		log.Fatalf("error creating resolver: %s", err)
	}

	res, s, err := CheckHost(net.ParseIP("0.0.0.0"), "google.com", "alt4.aspmx.l.google.com",
		WithResolver(r),
		WithListener(&printer{w: os.Stdout}),
	)
	if err != nil {
		log.Fatal(res, s, err)
	}

	// Output:
	// CHECK_HOST("0.0.0.0", "google.com", "alt4.aspmx.l.google.com")
	//   SPF: v=spf1 include:_spf.google.com ~all
	//   v=spf1
	//   include:_spf.google.com
	//
	//   CHECK_HOST("0.0.0.0", "_spf.google.com", "alt4.aspmx.l.google.com")
	//     SPF: v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all
	//     v=spf1
	//     include:_netblocks.google.com
	//
	//     CHECK_HOST("0.0.0.0", "_netblocks.google.com", "alt4.aspmx.l.google.com")
	//       SPF: v=spf1 ip4:64.18.0.0/20 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:207.126.144.0/20 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ip4:216.239.32.0/19 ~all
	//       v=spf1
	//       ip4:64.18.0.0/20
	//       ip4:64.233.160.0/19
	//       ip4:66.102.0.0/20
	//       ip4:66.249.80.0/20
	//       ip4:72.14.192.0/18
	//       ip4:74.125.0.0/16
	//       ip4:108.177.8.0/21
	//       ip4:173.194.0.0/16
	//       ip4:207.126.144.0/20
	//       ip4:209.85.128.0/17
	//       ip4:216.58.192.0/19
	//       ip4:216.239.32.0/19
	//       ~all
	//     = softfail, "", <nil>
	//
	//     include:_netblocks2.google.com
	//
	//     CHECK_HOST("0.0.0.0", "_netblocks2.google.com", "alt4.aspmx.l.google.com")
	//       SPF: v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36 ~all
	//       v=spf1
	//       ip6:2001:4860:4000::/36
	//       ip6:2404:6800:4000::/36
	//       ip6:2607:f8b0:4000::/36
	//       ip6:2800:3f0:4000::/36
	//       ip6:2a00:1450:4000::/36
	//       ip6:2c0f:fb50:4000::/36
	//       ~all
	//     = softfail, "", <nil>
	//
	//     include:_netblocks3.google.com
	//
	//     CHECK_HOST("0.0.0.0", "_netblocks3.google.com", "alt4.aspmx.l.google.com")
	//       SPF: v=spf1 ip4:172.217.0.0/19 ip4:108.177.96.0/19 ~all
	//       v=spf1
	//       ip4:172.217.0.0/19
	//       ip4:108.177.96.0/19
	//       ~all
	//     = softfail, "", <nil>
	//
	//     ~all
	//   = softfail, "", <nil>
	//
	//   ~all
	// = softfail, "", <nil>
}
