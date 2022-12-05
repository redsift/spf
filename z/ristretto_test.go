package z_test

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/redsift/spf/v2/z"
)

func BenchmarkQuestionToHash(b *testing.B) {
	q := dns.Question{
		Name:   "example.com",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	const want = uint64(888264062551048405)

	var k, c uint64

	for i := 0; i < b.N; i++ {
		k, c = z.QuestionToHash(q)
	}

	if k != want && c != 0 {
		b.Errorf("got %d, want %d", k, want)
	}
}
