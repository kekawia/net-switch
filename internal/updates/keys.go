package updates

import (
	"bytes"
	"errors"
)

// DevelopmentRootPublicKey has a deliberately public test seed. Release builds
// must replace RootPublicKey with the owner's offline root public key first.
const DevelopmentRootPublicKey = "RWT0UwsSU16NqzRAK3Xc8jcwt5D4sjx9KWlcL6NG6glo9+8l6OYqSGBR"
const RootPublicKey = DevelopmentRootPublicKey

func CheckProductionRoot() error {
	return checkProductionRoot(RootPublicKey)
}

func checkProductionRoot(public string) error {
	key, err := publicKeyBytes(public)
	if err != nil {
		return err
	}
	development, err := publicKeyBytes(DevelopmentRootPublicKey)
	if err != nil {
		return err
	}
	// Comments and key IDs do not change the public development private key.
	if bytes.Equal(key[10:], development[10:]) {
		return errors.New("production release refused: the development update root is still configured")
	}
	return nil
}
