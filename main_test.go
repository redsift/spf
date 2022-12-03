package spf

import (
	"fmt"
	"github.com/bluele/gcache"
	"github.com/miekg/dns"
	testing2 "github.com/redsift/spf/v2/testing"
	"os"
	"testing"
)

var (
	testResolver      Resolver
	testResolverCache gcache.Cache
)

func TestMain(m *testing.M) {
	s, err := testing2.StartDNSServer("udp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Errorf("unable to run local DNS server: %w", err))
	}

	dns.HandleFunc(".", testing2.RootZone)

	defer func() {
		dns.HandleRemove(".")
		_ = s.Shutdown()
	}()

	testResolverCache = gcache.New(100).Simple().Build()

	testResolver, _ = NewMiekgDNSResolver(s.PacketConn.LocalAddr().String(),
		MiekgDNSCache(testResolverCache),
		MiekgDNSParallelism(1))
	os.Exit(m.Run())
}
