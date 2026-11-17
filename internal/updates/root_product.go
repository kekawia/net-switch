//go:build !lifecycle_test

package updates

// Replace only this production anchor at the approved offline-root ceremony.
// Until then, CheckProductionRoot deliberately refuses release publication.
const RootPublicKey = DevelopmentRootPublicKey
