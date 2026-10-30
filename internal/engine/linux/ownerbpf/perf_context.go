package ownerbpf

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var skbAddressField = regexp.MustCompile(`field:\s*(?:const\s+)?void\s*\*\s*skbaddr;\s*offset:\s*([0-9]+);\s*size:\s*([0-9]+);`)

func checkConsumeFormat(format string) error {
	m := skbAddressField.FindStringSubmatch(format)
	if len(m) != 3 || m[1] != "8" || m[2] != "8" {
		return errors.New("unsupported consume_skb trace context: require skbaddr pointer at offset 8, size 8; no guessed offsets")
	}
	return nil
}

func onlineCPUs(s string) ([]int, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, fmt.Errorf("unsupported online CPU list %q (proof bound 512)", s)
	}
	var result []int
	last := -1
	for _, part := range strings.Split(trimmed, ",") {
		a, b, rangeOK := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		hi := lo
		if rangeOK && err == nil {
			hi, err = strconv.Atoi(b)
		}
		if err != nil || lo <= last || hi < lo || hi >= 512 {
			return nil, fmt.Errorf("unsupported online CPU list %q (proof bound 512)", s)
		}
		for cpu := lo; cpu <= hi; cpu++ {
			result = append(result, cpu)
		}
		last = hi
	}
	return result, nil
}
