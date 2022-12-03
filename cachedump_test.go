package spf

import (
	"encoding/json"
	. "github.com/redsift/spf/v2/testing"
	"reflect"
	"testing"

	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

func TestCacheDump(t *testing.T) {
	dns.HandleFunc("multiline.test.", Zone(map[uint16][]string{
		dns.TypeTXT: {
			`multiline.test. 0 IN TXT "v=spf1 ip4:10.0.0.1 ip4:10.0.0" ".2 -all"`,
		},
	}))
	defer dns.HandleRemove("multiline.test.")

	if _, _, err := testResolver.LookupTXT("multiline.test."); err != nil {
		t.Error(err)
	}

	dump := CacheDump(testResolverCache.GetALL(false))

	b, err := json.Marshal(dump)
	if err != nil {
		t.Error(err)
	}

	var c CacheDump

	if err := json.Unmarshal(b, &c); err != nil {
		t.Error(err)
	}

	gc := gcache.New(1).Build()
	r, _ := NewMiekgDNSResolver("0.0.0.0:0", MiekgDNSCache(gc))
	c.ForEach(r.CacheResponse)

	if !reflect.DeepEqual(testResolverCache.GetALL(false), gc.GetALL(false)) {
		t.Error("want equal got different")
	}
}
