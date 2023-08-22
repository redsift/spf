package printer

import (
	"encoding/json"
	"fmt"
	"github.com/outcaste-io/ristretto"
	"github.com/redsift/spf/v2/z"
	"log"
	"net"
	"os"

	"github.com/redsift/spf/v2"
)

func ExamplePrinter() {
	dump := []byte(`[
		";aspmx2.googlemail.com.   IN AAAA", "tZyBgAABAAEAAAAABmFzcG14Mgpnb29nbGVtYWlsA2NvbQAAHAABBmFzcG14Mgpnb29nbGVtYWlsA2NvbQAAHAABAAABJAAQKgAUUEAQDAUAAAAAAAAAGw==",
		";alt2.aspmx.l.google.com. IN A",    "rgaBgAABAAEAAAAABGFsdDIFYXNwbXgBbAZnb29nbGUDY29tAAABAAEEYWx0MgVhc3BteAFsBmdvb2dsZQNjb20AAAEAAQAAASQABEp9yBo=",
		";alt1.aspmx.l.google.com. IN A",    "t8eBgAABAAEAAAAABGFsdDEFYXNwbXgBbAZnb29nbGUDY29tAAABAAEEYWx0MQVhc3BteAFsBmdvb2dsZQNjb20AAAEAAQAAAJgABEDpoRo=",
		";spf.mailjet.com.         IN TXT",  "HUKBgAABAAEAAAAAA3NwZgdtYWlsamV0A2NvbQAAEAABA3NwZgdtYWlsamV0A2NvbQAAEAABAAAF0wCZmHY9c3BmMSBpcDQ6MTc4LjMzLjExMS4xNDQgaXA0OjE3OC4zMy4xMzcuMjA4LzI4IGlwNDoxNzguMzMuMjIxLjAvMjQgaXA0OjM3LjU5LjY5LjEyOC8yNSBpcDQ6MzcuNTkuMjQ5LjAvMjQgaXA0Ojg3LjI1My4yMzIuMC8yMSBpcDQ6MTg1LjE4OS4yMzYuMC8yMiA/YWxs",
		";servers.mcsv.net.        IN TXT",  "xruBgAABAAEAAAAAB3NlcnZlcnMEbWNzdgNuZXQAABAAAQdzZXJ2ZXJzBG1jc3YDbmV0AAAQAAEAAACYAEdGdj1zcGYxIGlwNDoyMDUuMjAxLjEyOC4wLzIwIGlwNDoxOTguMi4xMjguMC8xOCBpcDQ6MTQ4LjEwNS44LjAvMjEgP2FsbA==",
		";alt2.aspmx.l.google.com. IN AAAA", "duCBgAABAAEAAAAABGFsdDIFYXNwbXgBbAZnb29nbGUDY29tAAAcAAEEYWx0MgVhc3BteAFsBmdvb2dsZQNjb20AABwAAQAAASQAECQEaABAAwwAAAAAAAAAABo=",
		";blocket.se.              IN MX",   "sMSBgAABAAUAAAAAB2Jsb2NrZXQCc2UAAA8AAQdibG9ja2V0AnNlAAAPAAEAAAG7ABkAHgZhc3BteDMKZ29vZ2xlbWFpbANjb20AB2Jsb2NrZXQCc2UAAA8AAQAAAbsAGwAUBGFsdDEFYXNwbXgBbAZnb29nbGUDY29tAAdibG9ja2V0AnNlAAAPAAEAAAG7ABsAFARhbHQyBWFzcG14AWwGZ29vZ2xlA2NvbQAHYmxvY2tldAJzZQAADwABAAABuwAZAB4GYXNwbXgyCmdvb2dsZW1haWwDY29tAAdibG9ja2V0AnNlAAAPAAEAAAG7ABYACgVhc3BteAFsBmdvb2dsZQNjb20A",
		";aspmx.l.google.com.      IN AAAA", "ul2BgAABAAEAAAAABWFzcG14AWwGZ29vZ2xlA2NvbQAAHAABBWFzcG14AWwGZ29vZ2xlA2NvbQAAHAABAAABJAAQKgAUUEAMDAsAAAAAAAAAGw==",
		";aspmx.l.google.com.      IN A",    "IG+BgAABAAEAAAAABWFzcG14AWwGZ29vZ2xlA2NvbQAAAQABBWFzcG14AWwGZ29vZ2xlA2NvbQAAAQABAAABJAAEQOm4Gg==",
		";alt1.aspmx.l.google.com. IN AAAA", "Pp2BgAABAAEAAAAABGFsdDEFYXNwbXgBbAZnb29nbGUDY29tAAAcAAEEYWx0MQVhc3BteAFsBmdvb2dsZQNjb20AABwAAQAAASQAECoAFFBAEAwFAAAAAAAAABo=",
		";aspmx2.googlemail.com.   IN A",    "hJGBgAABAAEAAAAABmFzcG14Mgpnb29nbGVtYWlsA2NvbQAAAQABBmFzcG14Mgpnb29nbGVtYWlsA2NvbQAAAQABAAAAzQAEQOmhGw==",
		";aspmx3.googlemail.com.   IN AAAA", "3H2BgAABAAEAAAAABmFzcG14Mwpnb29nbGVtYWlsA2NvbQAAHAABBmFzcG14Mwpnb29nbGVtYWlsA2NvbQAAHAABAAABJAAQJARoAEADDAAAAAAAAAAAGg==",
		";subito.it.               IN TXT",  "R0aBgAABAAIAAAAABnN1Yml0bwJpdAAAEAABBnN1Yml0bwJpdAAAEAABAAABDQGr/3Y9c3BmMSBteDpibG9ja2V0LnNlIGluY2x1ZGU6c3BmLm1haWxqZXQuY29tIGluY2x1ZGU6c2VydmVycy5tY3N2Lm5ldCBpcDQ6MTA5LjE2OC4xMjcuMTYwLzI3IGlwNDoyMTIuMzEuMjUyLjY0LzI3IGlwNDoyMTIuNzcuNjguNiBpcDQ6NjIuMjEyLjEuMTYwIGlwNDo2Mi4yMTIuMC4xNjAgaXA0OjkzLjk0LjMyLjAvMjEgaXA0OjkzLjk0LjM3LjI1MyBpcDQ6MTA5LjE2OC4xMjEuNDgvMjggaXA0OjM3LjIwMi4yMC4yMy8zMiBpcDQ6MjEzLjIxNS4xNaoyLjI1NC8zMiBpcDQ6MjEzLjIxNS4xNTIuMjUzLzMyIGlwNDoyMTMuMjE1LjE1Mi4yNTIvMzIgaXA0OjIxMy4yMTUuMTUyLjI1MS8zMiBpcDQ6MTA5LjE2OC4xMjEuNTQvMzIgaXA0OjEwOS4xNjguMTIxLjU1LzMyIGlwNDoxMDkuMTY4LjEyMS41Ny8zMiBpcDQ6MTA5LjE2OC4xMjEuNTgvMzIgLWFsbAZzdWJpdG8CaXQAABAAAQAAAQ0ARURnb29nbGUtc2l0ZS12ZXJpZmljYXRpb249NXZqME5OR2FXZGtDaUJCd01EcUF5WE90aWsxejR1SF9Wc0dKbDNfY3djOA==",
		";ptr.test.redsift.io.     IN TXT",  "O7yBgAABAAEAAAAAA3B0cgR0ZXN0B3JlZHNpZnQCaW8AABAAAQNwdHIEdGVzdAdyZWRzaWZ0AmlvAAAQAAEAAAErABAPdj1zcGYxIHB0ciB+YWxs",
		";aspmx3.googlemail.com.   IN A",    "j2WBgAABAAEAAAAABmFzcG14Mwpnb29nbGVtYWlsA2NvbQAAAQABBmFzcG14Mwpnb29nbGVtYWlsA2NvbQAAAQABAAABJAAESn3IGg=="
		]`)

	// fill dns cache
	var d spf.CacheDump
	if err := json.Unmarshal(dump, &d); err != nil {
		log.Fatal(err)
	}

	c := z.MustRistrettoCache(&ristretto.Config{
		NumCounters: int64(100 * 10),
		MaxCost:     1 << 20,
		BufferItems: 64,
		Metrics:     true,
		KeyToHash:   z.QuestionToHash,
		Cost:        z.MsgCost,
	})
	// use resolver with cache and no parallelism
	r, err := spf.NewMiekgDNSResolver("8.8.8.8:53", spf.MiekgDNSParallelism(1), spf.MiekgDNSCache(c))
	if err != nil {
		log.Fatalf("error creating resolver: %s", err)
	}

	d.ForEach(r.CacheResponse)

	c.Wait()

	// create a printer
	p := New(os.Stdout, r)

	res, s, _, err := spf.CheckHost(net.ParseIP("0.0.0.0"), "subito.it", "aspmx.l.google.com",
		spf.WithResolver(p),
		spf.WithListener(p),
	)
	if err != nil {
		log.Fatalf("%s %q %s", res, s, err)
	}

	res, s, _, err = spf.CheckHost(net.ParseIP("0.0.0.0"), "ptr.test.redsift.io", "aspmx.l.google.com",
		spf.WithResolver(p),
		spf.WithListener(p),
	)
	if err != nil {
		log.Fatalf("%s %q %s", res, s, err)
	}
	fmt.Printf("## of lookups: %d\n", p.LookupsCount())

	// Unordered output:
	// CHECK_HOST("0.0.0.0", "subito.it.", "aspmx.l.google.com")
	//     lookup(TXT:strict) subito.it.
	//   SPF: v=spf1 mx:blocket.se include:spf.mailjet.com include:servers.mcsv.net ip4:109.168.127.160/27 ip4:212.31.252.64/27 ip4:212.77.68.6 ip4:62.212.1.160 ip4:62.212.0.160 ip4:93.94.32.0/21 ip4:93.94.37.253 ip4:109.168.121.48/28 ip4:37.202.20.23/32 ip4:213.215.152.254/32 ip4:213.215.152.253/32 ip4:213.215.152.252/32 ip4:213.215.152.251/32 ip4:109.168.121.54/32 ip4:109.168.121.55/32 ip4:109.168.121.57/32 ip4:109.168.121.58/32 -all
	//   v=spf1
	//   mx:blocket.se (blocket.se.)
	//     lookup(mx:blocket.se.) aspmx3.googlemail.com. -> (74.125.200.26/32 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) aspmx3.googlemail.com. -> (2404:6800:4003:c00::1a/128 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) alt1.aspmx.l.google.com. -> (64.233.161.26/32 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) alt1.aspmx.l.google.com. -> (2a00:1450:4010:c05::1a/128 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) alt2.aspmx.l.google.com. -> (74.125.200.26/32 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) alt2.aspmx.l.google.com. -> (2404:6800:4003:c00::1a/128 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) aspmx2.googlemail.com. -> (64.233.161.27/32 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) aspmx2.googlemail.com. -> (2a00:1450:4010:c05::1b/128 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) aspmx.l.google.com. -> (64.233.184.26/32 has? 0.0.0.0) = false
	//     lookup(mx:blocket.se.) aspmx.l.google.com. -> (2a00:1450:400c:c0b::1b/128 has? 0.0.0.0) = false
	//   include:spf.mailjet.com (spf.mailjet.com.)
	//   CHECK_HOST("0.0.0.0", "spf.mailjet.com.", "aspmx.l.google.com")
	//       lookup(TXT:strict) spf.mailjet.com.
	//     SPF: v=spf1 ip4:178.33.111.144 ip4:178.33.137.208/28 ip4:178.33.221.0/24 ip4:37.59.69.128/25 ip4:37.59.249.0/24 ip4:87.253.232.0/21 ip4:185.189.236.0/22 ?all
	//     v=spf1
	//     ip4:178.33.111.144 (178.33.111.144)
	//     ip4:178.33.137.208/28 (178.33.137.208/28)
	//     ip4:178.33.221.0/24 (178.33.221.0/24)
	//     ip4:37.59.69.128/25 (37.59.69.128/25)
	//     ip4:37.59.249.0/24 (37.59.249.0/24)
	//     ip4:87.253.232.0/21 (87.253.232.0/21)
	//     ip4:185.189.236.0/22 (185.189.236.0/22)
	//     ?all
	//   = neutral, &{1491000000000 false}, , <nil>
	//   include:servers.mcsv.net (servers.mcsv.net.)
	//   CHECK_HOST("0.0.0.0", "servers.mcsv.net.", "aspmx.l.google.com")
	//       lookup(TXT:strict) servers.mcsv.net.
	//     SPF: v=spf1 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.8.0/21 ?all
	//     v=spf1
	//     ip4:205.201.128.0/20 (205.201.128.0/20)
	//     ip4:198.2.128.0/18 (198.2.128.0/18)
	//     ip4:148.105.8.0/21 (148.105.8.0/21)
	//     ?all
	//   = neutral, &{152000000000 false}, , <nil>
	//   ip4:109.168.127.160/27 (109.168.127.160/27)
	//   ip4:212.31.252.64/27 (212.31.252.64/27)
	//   ip4:212.77.68.6 (212.77.68.6)
	//   ip4:62.212.1.160 (62.212.1.160)
	//   ip4:62.212.0.160 (62.212.0.160)
	//   ip4:93.94.32.0/21 (93.94.32.0/21)
	//   ip4:93.94.37.253 (93.94.37.253)
	//   ip4:109.168.121.48/28 (109.168.121.48/28)
	//   ip4:37.202.20.23/32 (37.202.20.23/32)
	//   ip4:213.215.152.254/32 (213.215.152.254/32)
	//   ip4:213.215.152.253/32 (213.215.152.253/32)
	//   ip4:213.215.152.252/32 (213.215.152.252/32)
	//   ip4:213.215.152.251/32 (213.215.152.251/32)
	//   ip4:109.168.121.54/32 (109.168.121.54/32)
	//   ip4:109.168.121.55/32 (109.168.121.55/32)
	//   ip4:109.168.121.57/32 (109.168.121.57/32)
	//   ip4:109.168.121.58/32 (109.168.121.58/32)
	//   -all
	// = fail, &{269000000000 false}, , <nil>
	// CHECK_HOST("0.0.0.0", "ptr.test.redsift.io.", "aspmx.l.google.com")
	//     lookup(TXT:strict) ptr.test.redsift.io.
	//   SPF: v=spf1 ptr ~all
	//   v=spf1
	//   ptr (ptr.test.redsift.io.)
	//     lookup(PTR) 0.0.0.0
	//   VOID: ptr, ptr.test.redsift.io.
	//   ~all
	// = softfail, &{299000000000 false}, , <nil>
	// ## of lookups: 15
}

// b, _ := spf.CacheDump(c.GetALL(false)).MarshalJSON()
// println(string(b))

func ExamplePrinter_ipv6nil() {
	dump := []byte(`[
		";_spf.q4press.com. IN TXT",  "FM+BgAABAAEAAAAABF9zcGYHcTRwcmVzcwNjb20AABAAAQRfc3BmB3E0cHJlc3MDY29tAAAQAAEAAAznAB4ddj1zcGYxIGE6d2ViLnE0cHJlc3MuY29tIC1hbGw=",
		";web.q4press.com.  IN AAAA", "USGBgAABAAEAAQAAA3dlYgdxNHByZXNzA2NvbQAAHAABA3dlYgdxNHByZXNzA2NvbQAABQABAABScQANB3E0cHJlc3MDY29tAAdxNHByZXNzA2NvbQAABgABAAADKwBIBm5zLTU3Mwlhd3NkbnMtMDcDbmV0ABFhd3NkbnMtaG9zdG1hc3RlcgZhbWF6b24DY29tAHga7IoAABwgAAADhAASdQAAAAEs",
		";q4press.com.      IN TXT",  "xPiBgAABAAIAAAAAB3E0cHJlc3MDY29tAAAQAAEHcTRwcmVzcwNjb20AABAAAQAAADsARURnb29nbGUtc2l0ZS12ZXJpZmljYXRpb249TjRTcU1hMjVVbHRVZjdlNnVBYm1jT2ttOUpCX0FidEw2Q245bjM5eFdRVQdxNHByZXNzA2NvbQAAEAABAAAAOwAlJHY9c3BmMSBpbmNsdWRlOl9zcGYucTRwcmVzcy5jb20gfmFsbA==",
		";web.q4press.com.  IN A",    "2caBgAABAAcAAAAAA3dlYgdxNHByZXNzA2NvbQAAAQABA3dlYgdxNHByZXNzA2NvbQAABQABAABUVwANB3E0cHJlc3MDY29tAAdxNHByZXNzA2NvbQAAAQABAAAAMwAEkhRbmQdxNHByZXNzA2NvbQAAAQABAAAAMwAEkhRbmAdxNHByZXNzA2NvbQAAAQABAAAAMwAEA9BKrAdxNHByZXNzA2NvbQAAAQABAAAAMwAEDTmJAwdxNHByZXNzA2NvbQAAAQABAAAAMwAENBdxiwdxNHByZXNzA2NvbQAAAQABAAAAMwAENrF2DQ=="
		]`)

	// fill dns cache
	var d spf.CacheDump
	if err := json.Unmarshal(dump, &d); err != nil {
		log.Fatal(err)
	}

	c := z.MustRistrettoCache(&ristretto.Config{
		NumCounters: int64(100 * 10),
		MaxCost:     1 << 20,
		BufferItems: 64,
		Metrics:     true,
		KeyToHash:   z.QuestionToHash,
		Cost:        z.MsgCost,
	})
	// use resolver with cache and no parallelism
	r, err := spf.NewMiekgDNSResolver("8.8.8.8:53", spf.MiekgDNSParallelism(1), spf.MiekgDNSCache(c))
	if err != nil {
		log.Fatalf("error creating resolver: %s", err)
	}

	d.ForEach(r.CacheResponse)

	c.Wait()

	// create a printer
	p := New(os.Stdout, r)

	res, s, _, err := spf.CheckHost(net.ParseIP("0.0.0.0"), "q4press.com", "aspmx.l.google.com",
		spf.WithResolver(p),
		spf.WithListener(p),
	)
	if err != nil {
		log.Fatalf("%s %q %s", res, s, err)
	}

	// Unordered output:
	// CHECK_HOST("0.0.0.0", "q4press.com.", "aspmx.l.google.com")
	//     lookup(TXT:strict) q4press.com.
	//   SPF: v=spf1 include:_spf.q4press.com ~all
	//   v=spf1
	//   include:_spf.q4press.com (_spf.q4press.com.)
	//   CHECK_HOST("0.0.0.0", "_spf.q4press.com.", "aspmx.l.google.com")
	//       lookup(TXT:strict) _spf.q4press.com.
	//     SPF: v=spf1 a:web.q4press.com -all
	//     v=spf1
	//     a:web.q4press.com (web.q4press.com.)
	//       lookup(a:web.q4press.com.) web.q4press.com. -> (146.20.91.153/32 has? 0.0.0.0) = false
	//       lookup(a:web.q4press.com.) web.q4press.com. -> (146.20.91.152/32 has? 0.0.0.0) = false
	//       lookup(a:web.q4press.com.) web.q4press.com. -> (3.208.74.172/32 has? 0.0.0.0) = false
	//       lookup(a:web.q4press.com.) web.q4press.com. -> (13.57.137.3/32 has? 0.0.0.0) = false
	//       lookup(a:web.q4press.com.) web.q4press.com. -> (52.23.113.139/32 has? 0.0.0.0) = false
	//       lookup(a:web.q4press.com.) web.q4press.com. -> (54.177.118.13/32 has? 0.0.0.0) = false
	//     -all
	//   = fail, &{3303000000000 false}, , <nil>
	//   ~all
	// = softfail, &{59000000000 false}, , <nil>
	//
}

func ExamplePrinter_voids() {
	// use resolver with cache and no parallelism
	r, err := spf.NewMiekgDNSResolver("8.8.8.8:53", spf.MiekgDNSParallelism(1))
	if err != nil {
		log.Fatalf("error creating resolver: %s", err)
	}

	// create a printer
	p := New(os.Stdout, r)

	res, s, _, err := spf.CheckHost(net.ParseIP("0.0.0.0"), "err008.spf.qa.redsift.tech", "redsift.io",
		spf.WithResolver(p),
		spf.WithListener(p),
		spf.IgnoreMatches(),
	)
	if err != nil {
		log.Fatalf("%s %q %s", res, s, err)
	}
	fmt.Printf("## of lookups: %d\n", p.LookupsCount())

	// Output:
	// CHECK_HOST("0.0.0.0", "err008.spf.qa.redsift.tech.", "redsift.io")
	//     lookup(TXT:strict) err008.spf.qa.redsift.tech.
	//   SPF: v=spf1 include:err008.1.spf.qa.redsift.tech -all
	//   v=spf1
	//   include:err008.1.spf.qa.redsift.tech (err008.1.spf.qa.redsift.tech.)
	//   CHECK_HOST("0.0.0.0", "err008.1.spf.qa.redsift.tech.", "redsift.io")
	//       lookup(TXT:strict) err008.1.spf.qa.redsift.tech.
	//     SPF: v=spf1 include:err008.2.spf.qa.redsift.tech include:err008.3.spf.qa.redsift.tech include:err008.4.spf.qa.redsift.tech -all
	//     v=spf1
	//     include:err008.2.spf.qa.redsift.tech (err008.2.spf.qa.redsift.tech.)
	//     CHECK_HOST("0.0.0.0", "err008.2.spf.qa.redsift.tech.", "redsift.io")
	//         lookup(TXT:strict) err008.2.spf.qa.redsift.tech.
	//       SPF: v=spf1 ip4:80.194.146.205 -all
	//       v=spf1
	//       ip4:80.194.146.205 (80.194.146.205)
	//       -all
	//     = fail, &{60000000000 false}, , <nil>
	//     include:err008.3.spf.qa.redsift.tech (err008.3.spf.qa.redsift.tech.)
	//     CHECK_HOST("0.0.0.0", "err008.3.spf.qa.redsift.tech.", "redsift.io")
	//         lookup(TXT:strict) err008.3.spf.qa.redsift.tech.
	//       VOID: , err008.3.spf.qa.redsift.tech.
	//     = none, &{0 true}, , permanent DNS error
	//     include:err008.4.spf.qa.redsift.tech (err008.4.spf.qa.redsift.tech.)
	//     CHECK_HOST("0.0.0.0", "err008.4.spf.qa.redsift.tech.", "redsift.io")
	//         lookup(TXT:strict) err008.4.spf.qa.redsift.tech.
	//       SPF: v=spf1 include:err008.5.spf.qa.redsift.tech include:err008.6.spf.qa.redsift.tech -all
	//       v=spf1
	//       include:err008.5.spf.qa.redsift.tech (err008.5.spf.qa.redsift.tech.)
	//       CHECK_HOST("0.0.0.0", "err008.5.spf.qa.redsift.tech.", "redsift.io")
	//           lookup(TXT:strict) err008.5.spf.qa.redsift.tech.
	//         VOID: , err008.5.spf.qa.redsift.tech.
	//       = none, &{0 true}, , SPF record not found
	//       include:err008.6.spf.qa.redsift.tech (err008.6.spf.qa.redsift.tech.)
	//       CHECK_HOST("0.0.0.0", "err008.6.spf.qa.redsift.tech.", "redsift.io")
	//           lookup(TXT:strict) err008.6.spf.qa.redsift.tech.
	//         VOID: , err008.6.spf.qa.redsift.tech.
	//       = none, &{0 true}, , permanent DNS error
	//       -all
	//     = permerror, &{60000000000 false}, , <nil>
	//     -all
	//   = permerror, &{60000000000 false}, , <nil>
	//   -all
	// = permerror, &{60000000000 false}, , <nil>
	// ## of lookups: 6

}
