package spferr

type Kind int8

const (
	KindUnknown Kind = iota
	KindSyntax
	KindValidation
	KindDNS
)

func (k Kind) String() string {
	switch k {
	case KindSyntax:
		return "syntax"
	case KindValidation:
		return "validation"
	case KindDNS:
		return "dns"
	default:
		return "unknown"
	}
}
