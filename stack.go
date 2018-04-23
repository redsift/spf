package spf

import (
	"errors"
)

type stringsStack struct {
	s []string
}

func newStringsStack() *stringsStack {
	return &stringsStack{make([]string, 0, 20)}
}

func (s *stringsStack) push(v string) {
	s.s = append(s.s, v)
}

func (s *stringsStack) pop() (string, error) {
	l := len(s.s)
	if l == 0 {
		return "", errors.New("empty stack")
	}

	res := s.s[l-1]
	s.s = s.s[:l-1]
	return res, nil
}

func (s *stringsStack) has(v string) bool {
	for _, str := range s.s {
		if v == str {
			return true
		}
	}
	return false
}
