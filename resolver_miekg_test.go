package spf

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/outcaste-io/ristretto"
	. "github.com/redsift/spf/v2/testing"
	"github.com/redsift/spf/v2/z"
	"net"
	"strings"
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
	dns.HandleFunc("multiline.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 0 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))
	defer dns.HandleRemove("multiline.test.")

	r, _, e := testResolver.LookupTXTStrict("multiline.test.")

	if e != nil {
		t.Fatal(e)
	}

	if len(r) != 1 {
		t.Errorf("want 1 got %d", len(r))
	}
}

func TestMiekgDNSResolver_Exists_Cached(t *testing.T) {
	testResolverCache.Clear()

	testResolverCache.Wait()

	delay := 500 * time.Millisecond
	dns.HandleFunc("slow.test.", WithDelay(Zone(map[uint16][]string{
		dns.TypeA: {
			`slow.test. 2 IN A 127.0.0.1`,
		},
	}), delay))
	defer dns.HandleRemove("slow.test.")

	start := time.Now()
	found, _, e := testResolver.Exists("slow.test.")
	d := time.Since(start)

	if !found {
		t.Error("unexpected response: want=true, got=false")
	}

	if e != nil {
		t.Fatal(e)
	}

	// Wait for the cache to be populated
	testResolverCache.Wait()

	if d < delay {
		t.Errorf("unexpected quick response: want=%v, got=%v", delay, d)
	}

	start = time.Now()
	_, _, e = testResolver.Exists("slow.test.")
	d = time.Since(start)

	if e != nil {
		t.Fatal(e)
	}

	if d > delay {
		t.Errorf("too slow response for cached response: want < %v, got=%v", delay, d)
	}

	// Wait for the cache to be expired
	time.Sleep(2 * time.Second)

	start = time.Now()
	testResolver.Exists("slow.test.")
	d = time.Since(start)

	if d < delay {
		t.Errorf("quick response for expired cache: want=%v, got=%v", delay, d)
	}
}

func TestMiekgDNSResolver_LookupTXT_Multiline(t *testing.T) {
	dns.HandleFunc("multiline.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 0 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))
	defer dns.HandleRemove("multiline.test.")

	r, _, e := testResolver.LookupTXT("multiline.test.")

	if e != nil {
		t.Fatal(e)
	}

	if len(r) != 1 {
		t.Errorf("want 1 got %d", len(r))
	}
}

func TestMiekgDNSResolver_CaseProd2(t *testing.T) {
	var got []string

	dnsCache := z.MustRistrettoCache(&ristretto.Config{
		NumCounters: int64(10 * 10),
		MaxCost:     1 << 20,
		BufferItems: 64,
		KeyToHash:   z.QuestionToHash,
		Cost:        z.MsgCost,
		OnEvict: func(item *ristretto.Item) {
			if item.Value == nil {
				return
			}
			got = append(got, item.Value.(*dns.Msg).Question[0].Name)
		},
	})

	client := new(dns.Client)
	client.Timeout = 800 * time.Millisecond

	r, err := NewMiekgDNSResolver("8.8.8.8:53", MiekgDNSClient(client), MiekgDNSCache(dnsCache))
	if err != nil {
		t.Fatalf("error creating resolver: %s", err)
	}

	// 172.217.31.1 is an address from _netblocks3.google.com., so checking it should unfold _spf.google.com
	res, s, _, err := CheckHost(net.ParseIP("172.217.31.1"), "google.com", "alt4.aspmx.l.google.com", WithResolver(r))
	if err != nil {
		t.Fatal(res, s, err)
	}

	// Wait for the cache to be populated
	dnsCache.Wait()

	// Trigger a "quantum" reading of the cache values
	dnsCache.Clear()

	want := []string{
		"google.com.",
		"_spf.google.com.",
		"_netblocks.google.com.",
		"_netblocks2.google.com.",
		"_netblocks3.google.com.",
	}

	less := func(l, r string) bool { return strings.Compare(l, r) < 0 }

	if diff := cmp.Diff(want, got, cmpopts.SortSlices(less)); diff != "" {
		t.Errorf("cached keys mismatch (-want +got):\n%s", diff)
	}
}

func TestMiekgDNSResolver_CaseProd1(t *testing.T) {
	client := new(dns.Client)
	resolver, err := NewMiekgDNSResolver("8.8.8.8:53", MiekgDNSClient(client))
	if err != nil {
		t.Fatal("Could not create resolver", err)
	}

	txts, _, err := resolver.LookupTXTStrict("thomsonreuters.com.")
	if err != nil {
		t.Fatal("Could not query TXTs", err)
	}

	if len(txts) == 0 {
		t.Error("No TXT records", txts)
	}
}

func TestMiekgDNSResolver_VoidLookups(t *testing.T) {
	dns.HandleFunc("void.test.", Zone(map[uint16][]string{}))
	defer dns.HandleRemove("void.test.")

	assertVoidLookup := func(t *testing.T, method func() ([]string, *ResponseExtras, error)) {
		answers, extras, _ := method()
		if len(answers) != 0 {
			t.Fatal("expected 0")
		}

		if extras == nil {
			t.Fatal("expected responseExtras")
		}

		if !extras.Void {
			t.Fatal("expected responseExtras.Void = true")
		}
	}

	// Subtest for LookupTXTVoid
	t.Run("LookupTXTVoid", func(t *testing.T) {
		// case 1 NOERROR
		assertVoidLookup(t, func() ([]string, *ResponseExtras, error) {
			return testResolver.LookupTXT("void.test.")
		})

		// case 2 NXDOMAIN
		assertVoidLookup(t, func() ([]string, *ResponseExtras, error) {
			return testResolver.LookupTXT("example.test.")
		})
	})

	// Subtest for LookupTXTStrictVoid
	t.Run("LookupTXTStrictVoid", func(t *testing.T) {
		// case 1 NOERROR
		assertVoidLookup(t, func() ([]string, *ResponseExtras, error) {
			return testResolver.LookupTXTStrict("void.test.")
		})

		// case 2 NXDOMAIN
		assertVoidLookup(t, func() ([]string, *ResponseExtras, error) {
			return testResolver.LookupTXTStrict("example.test.")
		})
	})

	// Subtest for ExistsVoid
	t.Run("ExistsVoid", func(t *testing.T) {

		// case 1 NOERROR
		found, extras, _ := testResolver.Exists("void.test.")
		if found {
			t.Fatal("expected false")
		}

		if extras == nil {
			t.Fatal("expected responseExtras")
		}

		if !extras.Void {
			t.Fatal("expected responseExtras.Void = true")
		}

		// case 2 NXDOMAIN
		found, extras, _ = testResolver.Exists("example.test.")
		if found {
			t.Fatal("expected false")
		}

		if extras == nil {
			t.Fatal("expected responseExtras")
		}

		if !extras.Void {
			t.Fatal("expected responseExtras.Void = true")
		}
	})

	// Subtest for LookupPTRVoid
	t.Run("LookupPTRVoid", func(t *testing.T) {
		// case 1 NOERROR
		assertVoidLookup(t, func() ([]string, *ResponseExtras, error) {
			return testResolver.LookupPTR("void.test.")
		})

		// case 2 NXDOMAIN
		assertVoidLookup(t, func() ([]string, *ResponseExtras, error) {
			return testResolver.LookupPTR("example.test.")
		})
	})
}
