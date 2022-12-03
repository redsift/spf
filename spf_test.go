package spf_test

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/redsift/spf"
)

func TestResult_MarshalJSON(t *testing.T) {
	tests := []struct {
		r       spf.Result
		want    []byte
		wantErr bool
	}{
		{spf.None, []byte(`"none"`), false},
		{spf.Neutral, []byte(`"neutral"`), false},
		{spf.Pass, []byte(`"pass"`), false},
		{spf.Fail, []byte(`"fail"`), false},
		{spf.Softfail, []byte(`"softfail"`), false},
		{spf.Temperror, []byte(`"temperror"`), false},
		{spf.Permerror, []byte(`"permerror"`), false},
		{spf.Result(101), []byte(`"101"`), false},
		{spf.Result(0), []byte(`"0"`), false},
	}

	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.r.String()), func(t *testing.T) {
			got, err := json.Marshal(test.r)
			if test.wantErr != (err != nil) {
				t.Errorf("json.Marshal() err=%v, wantErr=%t", err, test.wantErr)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("json.Marshal() got=%q, want=%q", got, test.want)
			}
		})
	}
}

func TestResult_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		s       string
		want    spf.Result
		wantErr bool
	}{
		{`"none"`, spf.None, false},
		{`"neutral"`, spf.Neutral, false},
		{`"pass"`, spf.Pass, false},
		{`"fail"`, spf.Fail, false},
		{`"softfail"`, spf.Softfail, false},
		{`"temperror"`, spf.Temperror, false},
		{`"permerror"`, spf.Permerror, false},
		{`"101"`, spf.Result(101), false},
		{`"0"`, spf.Result(0), false},
		{`"x"`, spf.Result(0), true},
	}

	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.s), func(t *testing.T) {
			var got spf.Result
			err := json.Unmarshal([]byte(test.s), &got)
			if test.wantErr != (err != nil) {
				t.Errorf("json.Unmarshal() err=%v, wantErr=%t", err, test.wantErr)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("json.Unmarshal() got=%q, want=%q", got, test.want)
			}
		})
	}
}

func TestCheckHost_Panic(t *testing.T) {
	r, err := spf.NewMiekgDNSResolver("8.8.8.8:53")
	if err != nil {
		t.Fatalf("NewMiekgDNSResolver() err=%s", err)
	}

	func() {
		defer func() {
			if x := recover(); x != nil {
				t.Errorf("CheckHost() panicked with: %v", x)
			}
		}()
		for i := 0; i < 500; i++ {
			_, _, _, _ = spf.CheckHost(net.ParseIP("0.0.0.0"), "mail.1stopnetworks.bm", "mail.1stopnetworks.bm", spf.WithResolver(r))
		}
	}()
}
