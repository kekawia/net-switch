package lifecycle

import "github.com/kekawia/net-switch/internal/updates"

func updateClient(data string) *updates.Client {
	return configureUpdateTestClient(data, &updates.Client{})
}
