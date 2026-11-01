package lifecycle

import "context"

// resumeEngine gives an attached engine ten seconds to receive a renewal
// after wake. It never decides routing intent: Control checks the owner's
// session after resume and stops routing itself if they signed out, so the
// Engine reads no sessions and does not hold SeTcbPrivilege.
func resumeEngine(server interface{ Resume() }, log func(string)) {
	server.Resume()
	log("power resume: ten-second lease renewal grace")
}

func Cleanup(ctx context.Context, data string) error {
	return cleanupNative(ctx, data)
}
