package spf

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestTrace_ReceivedSPF(t *testing.T) {
	tests := []struct {
		name  string
		trace *Trace
		want  string
	}{
		{
			"nil",
			nil,
			"",
		},
		{
			"pass",
			&Trace{Result: Pass},
			"pass (domain of sender designates the host as permitted sender)",
		},
		{
			"fail+ip+from+receiver",
			&Trace{
				Result:       Fail,
				Receiver:     "example.net",
				EnvelopeFrom: "john.doe@example.com",
				ClientIP:     net.ParseIP("1:0000::1"),
			},
			"fail (example.net: domain of john.doe@example.com does not designate 1::1 as permitted sender) client-ip=1::1; envelope-from=john.doe@example.com; receiver=example.net",
		},
		{
			"permerror+ip",
			&Trace{
				Result:   Permerror,
				ClientIP: net.ParseIP("1000::1"),
			},
			"permerror (a permanent error has occured) client-ip=1000::1",
		},
		{
			"permerror+ip+error",
			&Trace{
				Result:   Permerror,
				ClientIP: net.ParseIP("1000::1"),
				Problem:  errors.New("people afraid to use bicycles on the roads"),
			},
			"permerror (a permanent error has occured) client-ip=1000::1; problem=people afraid to use bicycles on the roads",
		},
		{
			"temperror+ip+mechanism+from",
			&Trace{
				Result:       Temperror,
				ClientIP:     net.ParseIP("127.0.0.1"),
				Mechanism:    "default",
				EnvelopeFrom: "john.doe@example.com",
			},
			"temperror (a transient error has occured) client-ip=127.0.0.1; envelope-from=john.doe@example.com; mechanism=default",
		},
		{
			"temperror+ip+error+explanation",
			&Trace{
				Result:      Temperror,
				ClientIP:    net.ParseIP("1000::1"),
				Problem:     errors.New("people afraid to use bicycles on the roads"),
				Explanation: "motorists either do not treat cyclist as equals or just can't spot them because of difference of speed",
			},
			"temperror (motorists either do not treat cyclist as equals or just can't spot them because of difference of speed) client-ip=1000::1; problem=people afraid to use bicycles on the roads",
		},
	}

	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.name), func(t *testing.T) {
			got := test.trace.ReceivedSPF()
			if got != test.want {
				t.Errorf("ReceivedSPF() got=%q, want=%q", got, test.want)
			}
		})
	}
}
