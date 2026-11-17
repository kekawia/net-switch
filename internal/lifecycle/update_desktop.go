package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/kekawia/net-switch/internal/localipc"
)

func requestUpdateDesktopRestart(_ context.Context, operation string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rpc, err := ConnectStatus(ctx)
	if err != nil {
		return err
	}
	var reply struct {
		PreviousPID uint32 `json:"previousPID"`
	}
	err = rpc.Call(ctx, map[string]any{"method": "desktop-restart", "key": operation}, &reply)
	rpc.Close()
	if err != nil {
		return err
	}
	for {
		rpc, err := ConnectStatus(ctx)
		if err != nil {
			return err
		}
		var status struct {
			DesktopPID uint32 `json:"desktopPID"`
		}
		err = rpc.Call(ctx, map[string]any{"method": "status"}, &status)
		rpc.Close()
		if err != nil {
			return err
		}
		if status.DesktopPID != 0 && status.DesktopPID != reply.PreviousPID {
			return nil
		}
		if err := localipc.Pause(ctx, 100*time.Millisecond); err != nil {
			return errors.New("updated desktop did not reconnect")
		}
	}
}
