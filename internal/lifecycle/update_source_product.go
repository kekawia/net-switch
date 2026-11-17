//go:build !lifecycle_test

package lifecycle

import "github.com/kekawia/net-switch/internal/updates"

func configureUpdateTestClient(_ string, client *updates.Client) *updates.Client { return client }
func updateTestInstallerArgs(string) []string                                    { return nil }
func updateTestHealthError(string) error                                         { return nil }
