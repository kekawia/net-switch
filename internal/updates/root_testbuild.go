//go:build lifecycle_test

package updates

// Instrumented hosted installers use a public fixture anchor independently of
// the production key. This build can never pass CheckProductionRoot, and the
// installer builder refuses this instrumentation on release tags.
const RootPublicKey = DevelopmentRootPublicKey
