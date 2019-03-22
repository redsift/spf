package spf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/miekg/dns"
)

type CacheDump map[interface{}]interface{}

func (c CacheDump) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer

	if c == nil {
		buf.WriteString("null")
		return buf.Bytes(), nil
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

	buf.WriteByte('[')
	buf.WriteByte('\n')
	i := 0
	for _, v := range c {
		if i > 0 {
			buf.WriteByte(',')
			buf.WriteByte('\n')
		}
		msg, _ := v.(*dns.Msg)

		b, err := msg.Pack()
		if err != nil {
			return nil, err
		}

		buf.WriteByte('"')
		if len(msg.Question) > 0 {
			buf.WriteByte(';')
			q := msg.Question[0]
			buf.WriteString(q.Name)
			buf.Write(bytes.Repeat([]byte{' '}, longestName-len(q.Name)))
			buf.WriteByte(' ')
			buf.WriteString(dns.Class(q.Qclass).String())
			buf.WriteByte(' ')
			typ := dns.Type(q.Qtype).String()
			buf.WriteString(typ)
			buf.WriteString(`", `)
			buf.Write(bytes.Repeat([]byte{' '}, 4-len(typ)))
			buf.WriteByte('"')
		}
		buf.WriteString(base64.StdEncoding.EncodeToString(b))
		buf.WriteByte('"')
		i++
	}
	if i > 0 {
		buf.WriteByte('\n')
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
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

func (c CacheDump) ForEach(f func(*dns.Msg)) {
	if c == nil {
		return
	}
	for _, v := range c {
		f(v.(*dns.Msg))
	}
}
