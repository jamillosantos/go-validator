package validator_test

import (
	"regexp"
	"strconv"
	"testing"
)

var numberRegex = regexp.MustCompile("^[0-9]+$")

func isNumberParsing(number string) bool {
	_, err := strconv.ParseInt(number, 10, 64)
	return err == nil
}

func isNumberRegex(number string) bool {
	return numberRegex.MatchString(number)
}

func BenchmarkIsNumberParsing(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !isNumberParsing("10") {
			b.FailNow()
		}
	}
}

func BenchmarkIsNumberRegex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !isNumberRegex("10") {
			b.FailNow()
		}
	}
}
