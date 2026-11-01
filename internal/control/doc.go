// Package control owns Net Switch's settings, routing policy and HTTP API.
//
// Platform reads and engine operations stay behind injectable boundaries so
// recorded completions can exercise the same core as production. Service
// installation, IPC, leases and ownership journals live in internal/lifecycle
// and internal/service. The desired-policy journal and closure intents remain
// separate from the engine's OS-ownership journal.
package control
