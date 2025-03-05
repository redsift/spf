package spf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/redsift/spf/v2"
)

func TestIsSPFCandidate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "simple valid case",
			input:    "v=spf1",
			expected: true,
		},
		{
			name:     "valid with colon separator",
			input:    "v:spf1",
			expected: true,
		},
		{
			name:     "valid with whitespace before v",
			input:    "  v=spf1",
			expected: true,
		},
		{
			name:     "valid with whitespace after v",
			input:    "v  =spf1",
			expected: true,
		},
		{
			name:     "valid with whitespace around separator",
			input:    "v = spf1",
			expected: true,
		},
		{
			name:     "valid uppercase SPF",
			input:    "v=SPF1",
			expected: true,
		},
		{
			name:     "valid uppercase V",
			input:    "V=spf1",
			expected: true,
		},
		{
			name:     "valid with mixed case",
			input:    "V=sPf1",
			expected: true,
		},
		{
			name:     "valid with text before pattern",
			input:    "text v=spf1",
			expected: true,
		},
		{
			name:     "valid with text after pattern",
			input:    "v=spf1 additional text",
			expected: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "only whitespace",
			input:    "   ",
			expected: false,
		},
		{
			name:     "missing v",
			input:    "=spf1",
			expected: true,
		},
		{
			name:     "missing separator",
			input:    "vspf1",
			expected: false,
		},
		{
			name:     "missing spf",
			input:    "v=",
			expected: false,
		},
		{
			name:     "wrong separator",
			input:    "v-spf1",
			expected: false,
		},
		{
			name:     "only v",
			input:    "v",
			expected: false,
		},
		{
			name:     "only spf",
			input:    "spf",
			expected: false,
		},
		{
			name:     "complex valid case with multiple parts",
			input:    "header v=spf1 include:_spf.example.com ~all",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := spf.IsSPFCandidate(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkIsSPFCandidate(b *testing.B) {
	testCases := map[string]string{
		"Empty":            "",
		"Simple":           "v=spf1",
		"Complex":          "v=SPF1 include:_spf.example.com ~all",
		"NoSPF":            "This is a long string without any SPF information in it at all",
		"EmailHeader":      "header.from=example.org; spf=pass (google.com: domain of admin@example.org designates 12.34.56.78 as permitted sender) smtp.mailfrom=admin@example.org",
		"ExcessWhitespace": "   v   =   spf1   ",
	}

	for name, tc := range testCases {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				spf.IsSPFCandidate(tc)
			}
		})
	}
}
