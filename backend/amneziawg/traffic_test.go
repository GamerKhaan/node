package amneziawg

import (
	"context"
	"encoding/json"
	"github.com/pasarguard/node/common"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type actualPrefixFailure struct {
	deviceControl
	armed bool
}

func (d *actualPrefixFailure) IpcSet(s string) error {
	if d.armed {
		d.armed = false
		return d.deviceControl.IpcSet(s + "m1_deliberate_invalid_field=1\n")
	}
	return d.deviceControl.IpcSet(s)
}

// Invoked only by the owned M1 traffic runner. No production fault flag exists.
func TestN04TrafficHelper(t *testing.T) {
	path := os.Getenv("M1_TRAFFIC_FIXTURE")
	if path == "" {
		return
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var input struct {
		Config json.RawMessage
		Users  []*common.User
		Target []*common.User
	}
	if e = json.Unmarshal(raw, &input); e != nil {
		t.Fatal("fixture input invalid")
	}
	c, e := NewConfig(string(input.Config))
	if e != nil {
		t.Fatal(e)
	}
	a := newBackend(c, createManager)
	a.manager, e = createManager(c)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Shutdown()
	if e = a.SyncUsers(context.Background(), input.Users); e != nil {
		t.Fatal(e)
	}
	root := filepath.Dir(path)
	signal := func(name string) {
		if e = os.WriteFile(filepath.Join(root, name), []byte("ready\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	wait := func(name string) {
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if _, e = os.Stat(filepath.Join(root, name)); e == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("traffic coordinator timeout")
	}
	snap, e := a.manager.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if e = a.manager.Verify(snap, c, a.peers); e != nil {
		t.Fatal(e)
	}
	signal("fixture-ready")
	wait("fixture-mutate")
	a.manager.dev = &actualPrefixFailure{deviceControl: a.manager.dev, armed: true}
	if e = a.UpdateUsers(context.Background(), input.Target); e == nil || !a.contained {
		t.Fatal("real prefix error did not contain")
	}
	known := int64(0)
	for _, u := range input.Users {
		known += total(t, a, u.Email, false)
	}
	if known == 0 {
		t.Fatal("real traffic supplied no attributable known usage")
	}
	if e = a.UpdateUsers(context.Background(), input.Users); e == nil {
		t.Fatal("contained partial recreated peers")
	}
	signal("fixture-contained")
	wait("fixture-recover")
	if e = a.SyncUsers(context.Background(), input.Users); e != nil {
		t.Fatal(e)
	}
	if !a.accountingIncomplete || !a.Started() {
		t.Fatal("recovery lost sticky uncertainty or readiness")
	}
	signal("fixture-recovered")
	wait("fixture-finish")
	after := int64(0)
	for _, u := range input.Users {
		after += total(t, a, u.Email, false)
	}
	if after < known {
		t.Fatal("contain/recreate lost known traffic")
	}
	result, _ := json.Marshal(map[string]any{"real_official_partial_error": true, "contained": true, "known_bytes_before_recovery": known, "known_bytes_after_recovery": after, "accounting_incomplete_sticky": a.accountingIncomplete})
	if e = os.WriteFile(filepath.Join(root, "fixture-result.json"), result, 0600); e != nil {
		t.Fatal(e)
	}
	signal("fixture-complete")
}
