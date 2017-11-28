package printer

import (
	"log"
	"net"
	"os"

	"github.com/redsift/spf"
)

func ExamplePrinter() {
	r, err := spf.NewMiekgDNSResolver("8.8.8.8:53")
	if err != nil {
		log.Fatalf("error creating resolver: %s", err)
	}

	p := New(os.Stdout, r)

	res, s, err := spf.CheckHost(net.ParseIP("74.125.140.27"), "subito.it", "aspmx.l.google.com",
		spf.WithResolver(p),
		spf.WithListener(p),
	)
	if err != nil {
		log.Fatal(res, s, err)
	}

	// CHECK_HOST("74.125.140.27", "subito.it", "aspmx.l.google.com")
	//     dns(txt:strict)
	//   SPF: v=spf1 mx:blocket.se include:spf.mailjet.com include:servers.mcsv.net ip4:109.168.127.160/27 ip4:212.31.252.64/27 ip4:212.77.68.6 ip4:62.212.1.160 ip4:62.212.0.160 ip4:93.94.32.0/21 ip4:93.94.37.253 ip4:109.168.121.48/28 ip4:37.202.20.23/32 ip4:213.215.152.254/32 ip4:213.215.152.253/32 ip4:213.215.152.252/32 ip4:213.215.152.251/32 ip4:109.168.121.54/32 ip4:109.168.121.55/32 ip4:109.168.121.57/32 ip4:109.168.121.58/32 -all
	//   v=spf1
	//   mx:blocket.se
	//     dns(mx:blocket.se.) aspmx.l.google.com. -> 173.194.76.26 false <nil>
	//     dns(mx:blocket.se.) alt2.aspmx.l.google.com. -> 2404:6800:4003:c00::1a false <nil>
	//     dns(mx:blocket.se.) aspmx2.googlemail.com. -> 64.233.165.26 false <nil>
	//     dns(mx:blocket.se.) aspmx2.googlemail.com. -> 2a00:1450:4010:c08::1b false <nil>
	//     dns(mx:blocket.se.) aspmx3.googlemail.com. -> 74.125.200.26 false <nil>
	//     dns(mx:blocket.se.) aspmx3.googlemail.com. -> 2404:6800:4003:c00::1b false <nil>
	//     dns(mx:blocket.se.) alt1.aspmx.l.google.com. -> 64.233.165.26 false <nil>
	//     dns(mx:blocket.se.) aspmx.l.google.com. -> 2a00:1450:400c:c0b::1b false <nil>
	//     dns(mx:blocket.se.) alt1.aspmx.l.google.com. -> 2a00:1450:4010:c08::1a false <nil>
	//     dns(mx:blocket.se.) alt2.aspmx.l.google.com. -> 74.125.200.26 false <nil>
	//   include:spf.mailjet.com
	//
	//   CHECK_HOST("74.125.140.27", "spf.mailjet.com", "aspmx.l.google.com")
	//       dns(txt:strict)
	//     SPF: v=spf1 ip4:178.33.111.144 ip4:178.33.137.208/28 ip4:178.33.221.0/24 ip4:37.59.69.128/25 ip4:37.59.249.0/24 ip4:87.253.232.0/21 ip4:185.189.236.0/22 ?all
	//     v=spf1
	//     ip4:178.33.111.144
	//     ip4:178.33.137.208/28
	//     ip4:178.33.221.0/24
	//     ip4:37.59.69.128/25
	//     ip4:37.59.249.0/24
	//     ip4:87.253.232.0/21
	//     ip4:185.189.236.0/22
	//     ?all
	//   = neutral, "", <nil>
	//
	//   include:servers.mcsv.net
	//
	//   CHECK_HOST("74.125.140.27", "servers.mcsv.net", "aspmx.l.google.com")
	//       dns(txt:strict)
	//     SPF: v=spf1 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.8.0/21 ?all
	//     v=spf1
	//     ip4:205.201.128.0/20
	//     ip4:198.2.128.0/18
	//     ip4:148.105.8.0/21
	//     ?all
	//   = neutral, "", <nil>
	//
	//   ip4:109.168.127.160/27
	//   ip4:212.31.252.64/27
	//   ip4:212.77.68.6
	//   ip4:62.212.1.160
	//   ip4:62.212.0.160
	//   ip4:93.94.32.0/21
	//   ip4:93.94.37.253
	//   ip4:109.168.121.48/28
	//   ip4:37.202.20.23/32
	//   ip4:213.215.152.254/32
	//   ip4:213.215.152.253/32
	//   ip4:213.215.152.252/32
	//   ip4:213.215.152.251/32
	//   ip4:109.168.121.54/32
	//   ip4:109.168.121.55/32
	//   ip4:109.168.121.57/32
	//   ip4:109.168.121.58/32
	//   -all
	// = fail, "", <nil>
}
