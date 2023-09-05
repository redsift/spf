package spferr

import "strconv"

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

func (r Kind) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

func (r *Kind) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*r = 0
		return nil
	}
	switch s := string(text); s {
	case "unknown":
		*r = KindUnknown
		return nil
	case "syntax":
		*r = KindSyntax
		return nil
	case "validation":
		*r = KindValidation
		return nil
	case "dns":
		*r = KindDNS
		return nil
	default:
		i, err := strconv.Atoi(s)
		*r = Kind(i)
		return err
	}
}
