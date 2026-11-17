package updates

import "errors"

// DevelopmentRootPublicKey has a deliberately public test seed. Release builds
// must replace RootPublicKey with the owner's offline root public key first.
const DevelopmentRootPublicKey = "RWT0UwsSU16NqzRAK3Xc8jcwt5D4sjx9KWlcL6NG6glo9+8l6OYqSGBR"
const RootPublicKey = DevelopmentRootPublicKey

func CheckProductionRoot() error {
	if RootPublicKey == DevelopmentRootPublicKey {
		return errors.New("production release refused: the development update root is still configured")
	}
	_, err := publicKeyBytes(RootPublicKey)
	return err
}
