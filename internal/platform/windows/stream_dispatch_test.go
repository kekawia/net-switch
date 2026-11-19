package winplatform

import (
	"context"
	"reflect"
	"testing"

	"github.com/kekawia/net-switch/internal/platform/worker"
)

func TestStreamImageAndArguments(t *testing.T) {
	for _, tc := range []struct {
		mode, image string
		args        []string
	}{
		{"meters", "observer", []string{"worker", "meters"}},
		{"network", "observer", []string{"worker", "network"}},
		{"outside", "observer", []string{"worker", "outside", "--engine", "router"}},
		{"probe", "existing", []string{"worker", "probe"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			launched := false
			s := System{EnginePath: "router", StreamExecutable: "observer", Workers: worker.Supervisor{
				Executable: "existing",
				Launch: func(image string, args []string) (worker.Process, error) {
					launched = true
					cancel()
					if image != tc.image || !reflect.DeepEqual(args, tc.args) {
						t.Fatalf("launch %q %v", image, args)
					}
					return nil, context.Canceled
				},
			}}
			s.Stream(ctx, tc.mode, nil, func(error) {})
			if !launched {
				t.Fatal("worker was not launched")
			}
		})
	}
}
