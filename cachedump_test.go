package spf

import (
	"encoding/json"
	"github.com/google/go-cmp/cmp"
	"github.com/outcaste-io/ristretto"
	. "github.com/redsift/spf/v2/testing"
	"github.com/redsift/spf/v2/z"
	"testing"

	"github.com/miekg/dns"
)

func TestCacheDump(t *testing.T) {
	dns.HandleFunc("multiline.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 1 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))
	defer dns.HandleRemove("multiline.test.")

	want := make(map[any]any)

	{
		c := z.MustRistrettoCache(&ristretto.Config{
			NumCounters: int64(10),
			MaxCost:     1 << 20,
			BufferItems: 64,
			Metrics:     true,
			KeyToHash:   z.QuestionToHash,
			Cost:        z.MsgCost,
			OnEvict: func(item *ristretto.Item) {
				if item.Value == nil {
					return
				}
				msg := item.Value.(*dns.Msg)
				want[msg.Question[0]] = msg
			},
		})

		r, _ := NewMiekgDNSResolver(testNameServer.PacketConn.LocalAddr().String(), MiekgDNSCache(c))

		if _, _, err := r.LookupTXT("multiline.test."); err != nil {
			t.Error(err)
		}

		// Wait for the cache to be populated
		c.Wait()

		// Trigger a "quantum" reading of the cache values
		c.Clear()
	}

	wDump := CacheDump(want)

	b, err := json.Marshal(wDump)
	if err != nil {
		t.Error(err)
	}

	var gDump CacheDump

	if err := json.Unmarshal(b, &gDump); err != nil {
		t.Error(err)
	}

	got := make(map[any]any)

	{
		c := z.MustRistrettoCache(&ristretto.Config{
			NumCounters: int64(10),
			MaxCost:     1 << 20,
			BufferItems: 64,
			Metrics:     true,
			KeyToHash:   z.QuestionToHash,
			Cost:        z.MsgCost,
			OnEvict: func(item *ristretto.Item) {
				if item.Value == nil {
					return
				}
				msg := item.Value.(*dns.Msg)
				got[msg.Question[0]] = msg
			},
		})
		r, _ := NewMiekgDNSResolver(testNameServer.PacketConn.LocalAddr().String(), MiekgDNSCache(c))

		// Populate the cache
		gDump.ForEach(r.CacheResponse)

		// Wait for the cache to be populated
		c.Wait()

		// Trigger a "quantum" reading of the cache values
		c.Clear()
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("caches mismatch (-want +got):\n%s", diff)
	}
}
