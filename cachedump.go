package spf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/bluele/gcache"
	"github.com/miekg/dns"
)

type CacheDump map[interface{}]interface{}

func (c CacheDump) MarshalJSON() ([]byte, error) {
	var bb bytes.Buffer

	if c == nil {
		bb.WriteString("null")
		return bb.Bytes(), nil
	}

	bb.WriteByte('[')
	i := 0
	for _, v := range c {
		if i > 0 {
			bb.WriteByte(',')
		}
		msg, ok := v.(*dns.Msg)
		if !ok {
			return nil, errors.New("value is not a *dns.Msg")
		}

		b, err := msg.Pack()
		if err != nil {
			return nil, err
		}

		bb.WriteRune('"')
		bb.WriteString(base64.StdEncoding.EncodeToString(b))
		bb.WriteRune('"')
		i++
	}
	bb.WriteByte(']')
	return bb.Bytes(), nil
}

func (c *CacheDump) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}

	var values [][]byte
	if err := json.Unmarshal(b, &values); err != nil {
		return err
	}
	m := make(map[interface{}]interface{})
	for _, v := range values {
		msg := new(dns.Msg)
		if err := msg.Unpack(v); err != nil {
			return err
		}
		m[msg.Question[0]] = msg
	}
	*c = CacheDump(m)
	return nil
}

func (c CacheDump) UnloadTo(gc gcache.Cache) {
	if gc == nil {
		return
	}
	r := &miekgDNSResolver{cache: gc}
	for _, v := range c {
		r.cacheResponse(v.(*dns.Msg))
	}
}
