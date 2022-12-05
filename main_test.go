package spf

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/outcaste-io/ristretto"
	. "github.com/redsift/spf/v2/testing"
	"github.com/redsift/spf/v2/z"
	"os"
	"testing"
	"time"
)

var (
	testNameServer    *dns.Server
	testResolverCache *ristretto.Cache
	testResolver      Resolver
)

func TestMain(m *testing.M) {
	var err error

	testNameServer, err = StartDNSServer("udp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Errorf("unable to run local DNS server: %w", err))
	}

	dns.HandleFunc(".", RootZone)

	defer func() {
		dns.HandleRemove(".")
		testNameServer.Shutdown()
	}()

	testResolverCache = z.MustRistrettoCache(&ristretto.Config{
		NumCounters: int64(100 * 10),
		MaxCost:     1 << 20,
		BufferItems: 64,
		Metrics:     true,
		KeyToHash:   z.QuestionToHash,
		Cost:        z.MsgCost,
	})

	testResolver, _ = NewMiekgDNSResolver(testNameServer.PacketConn.LocalAddr().String(),
		MiekgDNSMinSaneTTL(100*time.Millisecond),
		MiekgDNSCache(testResolverCache),
		MiekgDNSParallelism(1))

	os.Exit(m.Run())
}
