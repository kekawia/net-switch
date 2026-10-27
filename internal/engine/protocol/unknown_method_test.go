package protocol

import (
	"context"
	"testing"
)

func TestUnknownMethodRejected(t *testing.T) {
	s, _, req := setup(t)
	r := req("unsupported-replay-operation")
	if reply := s.Handle(context.Background(), r); reply.Error != `unknown method "unsupported-replay-operation"` {
		t.Fatal("unsupported method was not explicitly rejected", reply)
	}
	call(t, s, req("renew"))
}
