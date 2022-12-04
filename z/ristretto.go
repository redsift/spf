package z

import (
	"github.com/cespare/xxhash"
	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
)

func MsgCost(v any) int64 {
	return int64(v.(*dns.Msg).Len())
}

func QuestionToHash(k any) (uint64, uint64) {
	q := k.(dns.Question)

	hash := xxhash.New()

	hash.Write([]byte(q.Name))
	hash.Write([]byte{byte(q.Qtype >> 8), byte(q.Qtype)})
	hash.Write([]byte{byte(q.Qclass >> 8), byte(q.Qclass)})

	return hash.Sum64(), 0
}

func MustRistrettoCache(cfg *ristretto.Config) *ristretto.Cache {
	c, err := ristretto.NewCache(cfg)
	if err != nil {
		panic(err)
	}

	return c
}
