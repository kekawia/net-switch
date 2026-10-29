package ownerbpf

import (
	"errors"
	"regexp"
)

var skbAddressField = regexp.MustCompile(`field:\s*(?:const\s+)?void\s*\*\s*skbaddr;\s*offset:\s*([0-9]+);\s*size:\s*([0-9]+);`)

func checkConsumeFormat(format string) error {
	m := skbAddressField.FindStringSubmatch(format)
	if len(m) != 3 || m[1] != "8" || m[2] != "8" {
		return errors.New("unsupported consume_skb trace context: require skbaddr pointer at offset 8, size 8; no guessed offsets")
	}
	return nil
}
