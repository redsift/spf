package spf

import "testing"

func TestTokenSyntaxValidation(t *testing.T) {
	type TokenTestCase struct {
		token     *Token
		delimiter rune
		expected  bool
	}

	tests := []TokenTestCase{
		{nil, rune('='), false},
		{
			&Token{
				tInclude, qPlus, "matching.com",
			}, rune(':'), true,
		},
		{
			&Token{
				tInclude, qPlus, "",
			}, rune(':'), false,
		},
		{
			&Token{
				tErr, qErr, "",
			}, rune('='), true,
		},
		{
			&Token{
				tAll, qMinus, "matching.com",
			}, rune(':'), true,
		},
		{
			&Token{
				tAll, qMinus, "matching.com",
			}, rune('='), false,
		},
	}

	for _, test := range tests {
		token := test.token
		delimiter := test.delimiter
		expected := test.expected

		if checkTokenSyntax(token, delimiter) != expected {
			t.Errorf(
				"Error: For Token %v, delimiter %v got result %v, expected %v\n",
				*token, delimiter, !expected, expected)
		}
	}
}
