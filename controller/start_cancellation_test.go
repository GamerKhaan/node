package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/amneziawg"
	"github.com/pasarguard/node/common"
)

func TestStartCancellationScope(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, done := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer done()
	for _, ctx := range []context.Context{canceled, expired} {
		c := &Controller{}
		if !errors.Is(c.CheckStartCancellation(ctx, common.BackendType_AMNEZIAWG), ctx.Err()) {
			t.Fatal("canceled AWG target admitted")
		}
		for _, kind := range []common.BackendType{common.BackendType_WIREGUARD, common.BackendType_XRAY} {
			if c.CheckStartCancellation(ctx, kind) != nil {
				t.Fatal("ordinary legacy transition changed")
			}
		}
		c.backend = &amneziawg.AmneziaWG{}
		for _, kind := range []common.BackendType{common.BackendType_AMNEZIAWG, common.BackendType_WIREGUARD, common.BackendType_XRAY} {
			if !errors.Is(c.CheckStartCancellation(ctx, kind), ctx.Err()) {
				t.Fatal("canceled request can replace current AWG")
			}
			if c.CheckStartCancellation(context.Background(), kind) != nil {
				t.Fatal("valid request refused")
			}
		}
	}
}

func TestDirectCanceledAWGStartRefusedBeforeParsingOrCreating(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Controller{}
	err := c.StartBackend(ctx, &common.Backend{Type: common.BackendType_AMNEZIAWG, Config: "deliberately invalid"})
	if !errors.Is(err, context.Canceled) || c.Backend() != nil {
		t.Fatal("direct canceled AWG dispatch reached configuration/device side effects", err)
	}
}
