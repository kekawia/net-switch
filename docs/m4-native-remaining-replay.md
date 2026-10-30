# Remaining native trace slices

## quitFailure

The 175 entries use the shared startup driver and ledger v2. Both original
POST requests execute through HTTP and real Control. The first injected stop
failure returns the exact 400 response, resets quitting, retains the complete
session bytes and leaves Control uncancelled. It neither saves usage nor removes
anything. Both journal copies contain wanted:false before either stop attempt.

The retry starts from the retained error/PID observation, stops successfully,
saves usage through the existing file cursor, removes only server.json, cancels
Control and returns the exact successful response. All six diagnostics and
their effect order are checked. The simulated PID is a status observation;
no process is launched. Historical PID cleanup is an explicit replacement by
the acknowledged native stop, supported by TestNativeStartupSessionReplacement.

Pure Control, control/engine and ledger suites, plus the selected native
lifecycle startup and closure-fencing tests, pass through replay-report:
**6,608 / 7,894**, 1,286 uncovered, producer/lifecycle/report exits **0/0/0**.
No product behavior or frozen fixture was changed. Hosted race checks and
independent review remain pending.
