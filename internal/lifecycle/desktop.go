package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/desktop"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// Offline tests replace the transport; production always authenticates the
// real service endpoint.
var dialIPC = localipc.Dial

func controlEndpoint(kind string) localipc.Endpoint {
	return localipc.Endpoint{Path: localipc.DefaultPath(kind), Kind: kind, Service: service.Control}
}

func ConnectDesktop(ctx context.Context, status bool) (*RPC, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	kind := "desktop"
	if status {
		kind = "status"
	}
	conn, err := dialIPC(ctx, controlEndpoint(kind))
	if !status && localipc.Unavailable(err) {
		if activateErr := service.Activate(ctx); activateErr != nil {
			return nil, activateErr
		}
		for localipc.Unavailable(err) {
			if pauseErr := localipc.Pause(ctx, 100*time.Millisecond); pauseErr != nil {
				return nil, pauseErr
			}
			conn, err = dialIPC(ctx, controlEndpoint(kind))
		}
	}
	if err != nil {
		return nil, err
	}
	return NewRPC(conn), nil
}

// ConnectStatus opens a connection for status without explicitly activating
// Control. Linux's public fallback retains normal socket activation. Every
// signed-in user may open the public endpoint, so one of them
// can keep it busy (on Windows, idle opens hold its listening instance through
// each bounded identity read). Callers with protected rights (the owner, an
// elevated administrator, SYSTEM or root) therefore read status on the
// protected endpoint with its separate admission and owner access rules.
// Only a denied or missing protected endpoint falls back to
// the public, status-only one; any other failure is reported as is.
func ConnectStatus(ctx context.Context) (*RPC, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := dialIPC(ctx, controlEndpoint("desktop"))
	if localipc.Unavailable(err) || errors.Is(err, fs.ErrPermission) {
		conn, err = dialIPC(ctx, controlEndpoint("status"))
	}
	if err != nil {
		return nil, err
	}
	return NewRPC(conn), nil
}

// ConfigureAutostart is the per-user installer hook. It writes only the
// enrolled user's Run key/XDG entry; it does not turn routing on.
func ConfigureAutostart(ctx context.Context, mode string) (any, error) {
	if mode != "on" && mode != "off" && mode != "status" {
		return nil, fmt.Errorf("autostart must be on, off or status")
	}
	if err := service.Activate(ctx); err != nil {
		return nil, err
	}
	rpc, err := ConnectDesktop(ctx, false)
	if err != nil {
		return nil, err
	}
	defer rpc.Close()
	if err := rpc.Call(ctx, map[string]any{"method": "session"}, nil); err != nil {
		return nil, err
	}
	if mode == "status" {
		return DesktopCall(ctx, "autostart", nil)
	}
	return DesktopCall(ctx, "autostart-set", map[string]any{"on": mode == "on"})
}

var (
	testDesktopSeq       atomic.Uint64
	desktopStateInterval = desktop.PollInterval
	desktopScope         = func() string {
		if testing.Testing() {
			return fmt.Sprintf("test-%d", testDesktopSeq.Add(1))
		}
		return ""
	}
	startDesktopUI = func(cb desktop.UICallbacks) desktop.UI {
		return desktop.NoopUI{}
	}
)

// SetDesktopUIFactory installs the platform UI constructor used by Desktop.
func SetDesktopUIFactory(fn func(desktop.UICallbacks) desktop.UI) {
	if fn != nil {
		startDesktopUI = fn
	}
}

type desktopRuntime struct {
	mu        sync.Mutex
	ui        desktop.UI
	rpc       *RPC
	client    *desktop.Client
	refreshCh chan struct{}
	quitting  atomic.Bool
	quitOnce  sync.Once
	quitDone  chan struct{}
	cancelRun context.CancelFunc
}

func (r *desktopRuntime) triggerPoll() {
	select {
	case r.refreshCh <- struct{}{}:
	default:
	}
}

func (r *desktopRuntime) openPair(ctx context.Context) (string, string, string, error) {
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	if rpc == nil {
		return "", "", "", errors.New("Control is not connected")
	}
	var session struct {
		URL   string `json:"url"`
		Owner string `json:"ownerName"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "session"}, &session); err != nil {
		return "", "", "", err
	}
	var code string
	if err := rpc.Call(ctx, map[string]any{"method": "pair"}, &code); err != nil {
		return "", "", "", err
	}
	return strings.TrimRight(session.URL, "/") + "/pair", code, session.Owner, nil
}

func (r *desktopRuntime) refreshToken(ctx context.Context) (string, bool) {
	r.mu.Lock()
	rpc := r.rpc
	client := r.client
	ui := r.ui
	r.mu.Unlock()
	if rpc == nil {
		return "", false
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var session struct {
		Token string `json:"token"`
		URL   string `json:"url"`
		Owner string `json:"ownerName"`
	}
	if err := rpc.Call(cctx, map[string]any{"method": "session"}, &session); err != nil || session.Token == "" {
		return "", false
	}
	if client != nil {
		_ = client.SetEndpoint(session.URL, session.Token)
	}
	if ui != nil {
		ui.SetSession(session.URL, session.Token, session.Owner)
	}
	return session.Token, true
}

func (r *desktopRuntime) runAction(key string, fn func(context.Context, *desktop.Client) error) {
	r.mu.Lock()
	client := r.client
	ui := r.ui
	r.mu.Unlock()
	if client == nil {
		if ui != nil {
			ui.SetActionFeedback("", "Net Switch isn\u2019t responding.")
		}
		return
	}
	if ui != nil {
		ui.SetActionFeedback(key, "")
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := fn(ctx, client)
		if ui != nil {
			if err != nil {
				ui.SetActionFeedback("", err.Error())
			} else {
				ui.SetActionFeedback("", "")
			}
		}
		r.triggerPoll()
	}()
}

func (r *desktopRuntime) requestQuit() {
	r.quitting.Store(true)
	r.quitOnce.Do(func() {
		r.mu.Lock()
		ui := r.ui
		client := r.client
		r.mu.Unlock()
		if ui != nil {
			ui.SetQuitting()
		}
		go func() {
			defer close(r.quitDone)
			if client != nil {
				qctx, qcancel := context.WithTimeout(context.Background(), 10*time.Second)
				_ = client.Quit(qctx)
				qcancel()
			}
			if r.cancelRun != nil {
				r.cancelRun()
			}
		}()
	})
}

func Desktop(ctx context.Context, show bool) error {
	showReq := make(chan struct{}, 1)
	lock, err := desktop.AcquireSingleInstance(ctx, desktopScope(), show, func() {
		select {
		case showReq <- struct{}{}:
		default:
		}
	})
	if err == nil && lock != nil && lock.AlreadyRunning {
		return nil
	}
	if lock != nil {
		defer lock.Close()
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	rt := &desktopRuntime{
		refreshCh: make(chan struct{}, 1),
		quitDone:  make(chan struct{}),
		cancelRun: cancelRun,
	}
	defer func() {
		rt.mu.Lock()
		ui := rt.ui
		rt.mu.Unlock()
		if ui != nil {
			ui.Close()
		}
	}()
	defer func() {
		if rt.quitting.Load() {
			<-rt.quitDone
		}
	}()

	// Only the sign-in entry point requests automatic routing. Reopening a
	// window must preserve an explicit Turn off or a latched recovery error.
	first := !show
	wantInitialShow := show
	backoff := time.Second
	for runCtx.Err() == nil {
		connectCtx, stop := context.WithTimeout(runCtx, 40*time.Second)
		// The owner uses the protected endpoint first. Public status load
		// cannot prevent a desktop from obtaining its own reserved slot.
		status, err := ConnectDesktop(connectCtx, false)
		if err != nil {
			if err = service.Activate(connectCtx); err == nil {
				status, err = ConnectDesktop(connectCtx, false)
			}
			if err != nil {
				status, err = ConnectDesktop(connectCtx, true)
			}
		}
		if err != nil {
			stop()
			if rt.quitting.Load() || runCtx.Err() != nil {
				return nil
			}
			fmt.Println("Net Switch is not ready; retrying:", err)
			if localipc.Pause(runCtx, backoff) != nil {
				return nil
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		var state struct {
			Owner   Owner  `json:"owner"`
			Routing string `json:"routing"`
		}
		err = status.Call(connectCtx, map[string]any{"method": "status"}, &state)
		status.Close()
		if err != nil {
			stop()
			if rt.quitting.Load() || runCtx.Err() != nil {
				return nil
			}
			if localipc.Pause(runCtx, backoff) != nil {
				return nil
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		if state.Owner.User == "" || state.Owner.User != CurrentUser() {
			stop()
			message := "Owner enrolment is pending. Ask an administrator to run netswitchctl enroll."
			if state.Owner.User != "" {
				message = fmt.Sprintf("Net Switch is set up for %s. Routing is %s. This account can view status only.", state.Owner.Name, state.Routing)
			}
			if show {
				return ShowStatus(message)
			}
			fmt.Println(message)
			return nil
		}

		// Owner verified: initialize UI shell once across Control reconnects.
		rt.mu.Lock()
		if rt.ui == nil {
			rt.ui = startDesktopUI(desktop.UICallbacks{
				OpenPair:     rt.openPair,
				RefreshToken: rt.refreshToken,
				ToggleRouting: func(wantOn bool) {
					rt.runAction("routing", func(cctx context.Context, c *desktop.Client) error {
						return c.SetRouting(cctx, wantOn)
					})
				},
				ToggleCombine: func(wantOn bool) {
					rt.runAction("combine", func(cctx context.Context, c *desktop.Client) error {
						return c.SetCombine(cctx, wantOn)
					})
				},
				SetAppLine: func(appPath string, line *string) {
					rt.runAction("app:"+appPath, func(cctx context.Context, c *desktop.Client) error {
						return c.SetAppLine(cctx, appPath, line)
					})
				},
				DismissUpdate: func(version string) {
					rt.runAction("update", func(cctx context.Context, c *desktop.Client) error {
						return c.DismissUpdate(cctx, version)
					})
				},
				Quit:           rt.requestQuit,
				FallbackStatus: ShowStatus,
			})
		}
		rt.mu.Unlock()

		rpc, err := ConnectDesktop(connectCtx, false)
		stop()
		if err != nil {
			if rt.quitting.Load() || runCtx.Err() != nil {
				return nil
			}
			if localipc.Pause(runCtx, backoff) != nil {
				return nil
			}
			continue
		}
		backoff = time.Second
		registered := false
		// Keep the sign-in intent until the server has acknowledged it.
		if first {
			signCtx, stop := context.WithTimeout(runCtx, 40*time.Second)
			err = rpc.Call(signCtx, map[string]any{"method": "signin"}, nil)
			stop()
			var rejected rpcError
			switch {
			case errors.As(err, &rejected):
				// Control answered and refused. Exiting would leave the
				// owner without Net Switch for the whole session, so stay
				// connected, show why, and let them act from the window.
				showRejectedSignIn(fmt.Sprintf("Net Switch did not turn routing on at sign-in: %v", err))
				first = false
			case err != nil:
				rpc.Close()
				if rt.quitting.Load() || runCtx.Err() != nil {
					return nil
				}
				if localipc.Pause(runCtx, backoff) != nil {
					return nil
				}
				continue
			default:
				first = false
				registered = true
			}
		}
		err = desktopSession(runCtx, rt, rpc, wantInitialShow, registered, showReq)
		wantInitialShow = false
		rpc.Close()
		if rt.quitting.Load() || runCtx.Err() != nil {
			return nil
		}
		fmt.Println("Net Switch connection lost; reconnecting:", err)
		first = false
		if err := localipc.Pause(runCtx, time.Second); err != nil {
			return nil
		}
	}
	return nil
}

// showRejectedSignIn reports a refused sign-in without blocking the desktop.
var showRejectedSignIn = func(message string) {
	fmt.Println(message)
	go func() { _ = ShowStatus(message) }()
}

func desktopSession(ctx context.Context, rt *desktopRuntime, rpc *RPC, show, registered bool, showReq <-chan struct{}) error {
	var session struct {
		Token string `json:"token"`
		URL   string `json:"url"`
		Owner string `json:"ownerName"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "session"}, &session); err != nil {
		return err
	}
	if !registered {
		// Reconnect metadata without turning routing back on after the owner
		// explicitly stopped it.
		if err := rpc.Call(ctx, map[string]any{"method": "desktop-connect"}, nil); err != nil {
			return err
		}
	}

	client, err := desktop.NewClient(session.URL, session.Token)
	if err == nil {
		client.SetUnauthorizedHook(rt.refreshToken)
	}
	rt.mu.Lock()
	rt.rpc = rpc
	rt.client = client
	ui := rt.ui
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		if rt.rpc == rpc {
			rt.rpc = nil
			rt.client = nil
		}
		rt.mu.Unlock()
	}()

	if ui != nil {
		ui.SetSession(session.URL, session.Token, session.Owner)
		if show {
			ui.ShowWindow("")
		}
	} else if show {
		var code string
		if err := rpc.Call(ctx, map[string]any{"method": "pair"}, &code); err != nil {
			return err
		}
		if err := ShowPairing(strings.TrimRight(session.URL, "/")+"/pair", code, session.Owner); err != nil {
			return err
		}
	}

	sessCtx, cancelSess := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancelSess()
		wg.Wait()
	}()

	if ui != nil && client != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pollOnce := func() {
				if rt.quitting.Load() || sessCtx.Err() != nil {
					return
				}
				state, fetchErr := client.FetchState(sessCtx)
				if rt.quitting.Load() || sessCtx.Err() != nil {
					return
				}
				ui.UpdateState(state, fetchErr == nil && state != nil)
			}
			pollOnce()
			interval := desktopStateInterval
			if interval <= 0 {
				interval = desktop.PollInterval
			}
			stateTick := time.NewTicker(interval)
			defer stateTick.Stop()
			for {
				select {
				case <-sessCtx.Done():
					return
				case <-rt.refreshCh:
					pollOnce()
				case <-stateTick.C:
					pollOnce()
				}
			}
		}()
	}

	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rpc.Done():
			cancelSess()
			wg.Wait()
			if ui != nil && !rt.quitting.Load() {
				ui.UpdateState(nil, false)
			}
			return fmt.Errorf("Control restarted")
		case <-showReq:
			if ui != nil {
				ui.ShowWindow("")
			}
		case <-tick.C:
			var tasks []DesktopWork
			if err := rpc.Call(ctx, map[string]any{"method": "desktop-poll"}, &tasks); err != nil {
				cancelSess()
				wg.Wait()
				if ui != nil && !rt.quitting.Load() {
					ui.UpdateState(nil, false)
				}
				return err
			}
			for _, task := range tasks {
				value, err := DesktopCall(ctx, task.Operation, task.Args)
				message := ""
				if err != nil {
					message = err.Error()
				}
				if err := rpc.Call(ctx, map[string]any{"method": "desktop-result", "key": task.ID, "value": value, "error": message}, nil); err != nil {
					cancelSess()
					wg.Wait()
					if ui != nil && !rt.quitting.Load() {
						ui.UpdateState(nil, false)
					}
					return err
				}
			}
		}
	}
}
