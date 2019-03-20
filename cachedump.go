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
	longestName := 0
	for _, v := range c {
		msg, ok := v.(*dns.Msg)
		if !ok {
			return nil, errors.New("value is not a *dns.Msg")
		}
		if len(msg.Question) > 0 && len(msg.Question[0].Name) > longestName {
			longestName = len(msg.Question[0].Name)
		}
	}

	bb.WriteByte('[')
	bb.WriteByte('\n')
	i := 0
	for _, v := range c {
		if i > 0 {
			bb.WriteByte(',')
			bb.WriteByte('\n')
		}
		msg, _ := v.(*dns.Msg)

		b, err := msg.Pack()
		if err != nil {
			return nil, err
		}

		bb.WriteByte('"')
		if len(msg.Question) > 0 {
			bb.WriteByte(';')
			q := msg.Question[0]
			bb.WriteString(q.Name)
			bb.Write(bytes.Repeat([]byte{' '}, longestName-len(q.Name)))
			bb.WriteByte(' ')
			bb.WriteString(dns.Class(q.Qclass).String())
			bb.WriteByte(' ')
			typ := dns.Type(q.Qtype).String()
			bb.WriteString(typ)
			bb.WriteString(`", `)
			bb.Write(bytes.Repeat([]byte{' '}, 4-len(typ)))
			bb.WriteByte('"')
		}
		bb.WriteString(base64.StdEncoding.EncodeToString(b))
		bb.WriteByte('"')
		i++
	}
	if i > 0 {
		bb.WriteByte('\n')
	}
	bb.WriteByte(']')
	return bb.Bytes(), nil
}

func (c *CacheDump) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}

	var values []string
	if err := json.Unmarshal(b, &values); err != nil {
		return err
	}
	m := make(map[interface{}]interface{})
	for _, v := range values {
		if len(v) > 0 && v[0] == ';' {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return err
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(b); err != nil {
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
