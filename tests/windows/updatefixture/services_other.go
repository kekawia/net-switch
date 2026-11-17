//go:build !windows

package main

import "errors"

func printServicePaths() error { return errors.New("service path inspection requires Windows") }
