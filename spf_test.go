package spf

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestResult_MarshalJSON(t *testing.T) {
	tests := []struct {
		r       Result
		want    []byte
		wantErr bool
	}{
		{None, []byte(`"none"`), false},
		{Neutral, []byte(`"neutral"`), false},
		{Pass, []byte(`"pass"`), false},
		{Fail, []byte(`"fail"`), false},
		{Softfail, []byte(`"softfail"`), false},
		{Temperror, []byte(`"temperror"`), false},
		{Permerror, []byte(`"permerror"`), false},
		{Result(101), []byte(`"101"`), false},
		{Result(0), []byte(`"0"`), false},
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
		want    Result
		wantErr bool
	}{
		{`"none"`, None, false},
		{`"neutral"`, Neutral, false},
		{`"pass"`, Pass, false},
		{`"fail"`, Fail, false},
		{`"softfail"`, Softfail, false},
		{`"temperror"`, Temperror, false},
		{`"permerror"`, Permerror, false},
		{`"101"`, Result(101), false},
		{`"0"`, Result(0), false},
		{`"x"`, Result(0), true},
	}

	const wantTest = -1
	for testNo, test := range tests {
		//noinspection GoBoolExpressions
		if wantTest > -1 && wantTest != testNo {
			continue
		}
		t.Run(fmt.Sprintf("%d_%s", testNo, test.s), func(t *testing.T) {
			var got Result
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
