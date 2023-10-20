package spf

import "testing"

func TestTokenSyntaxValidation(t *testing.T) {
	type TokenTestCase struct {
		token     *token
		delimiter rune
		expected  bool
	}

	tests := []TokenTestCase{
		{nil, rune('='), false},
		{
			&token{
				mechanism: tInclude, qualifier: qPlus, value: "matching.com",
			}, rune(':'), true,
		},
		{
			&token{
				mechanism: tInclude, qualifier: qPlus, value: "",
			}, rune(':'), false,
		},
		{
			&token{
				mechanism: tErr, qualifier: qErr, value: "",
			}, rune('='), true,
		},
		{
			&token{
				mechanism: tAll, qualifier: qMinus, value: "matching.com",
			}, rune(':'), true,
		},
		{
			&token{
				mechanism: tAll, qualifier: qMinus, value: "matching.com",
			}, rune('='), false,
		},
	}

	for _, test := range tests {
		token := test.token
		delimiter := test.delimiter
		expected := test.expected

		if checkTokenSyntax(token, delimiter) != expected {
			t.Errorf(
				"Error: For token %v, delimiter %v got result %v, expected %v\n",
				*token, delimiter, !expected, expected)
		}
	}
}
