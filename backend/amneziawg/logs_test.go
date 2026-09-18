// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"context"
	"strings"
	"testing"

	"github.com/pasarguard/node/common"
)

func TestAWGStructuredLogLine(t *testing.T) {
	got := awgEventLine(awgLogInfo, awgEventStart)
	if got != "[AWG] [info] event=start result=ok" {
		t.Fatalf("unexpected event line: %q", got)
	}
	got = awgEventLine(awgLogError, awgEventUAPIError)
	if got != "[AWG] [error] event=uapi_error result=failed" {
		t.Fatalf("unexpected error line: %q", got)
	}
}

func TestAWGStructuredEventFlowsThroughExistingLogChannel(t *testing.T) {
	backend := newBackend(&Config{}, nil)
	want := awgEventLine(awgLogInfo, awgEventStart)
	backend.emit(want)

	select {
	case got := <-backend.Logs():
		if got != want {
			t.Fatalf("unexpected streamed log: %q", got)
		}
	default:
		t.Fatal("structured AWG event was not published to the existing log channel")
	}
}

func TestAWGPeerChangeLogContainsCountsOnly(t *testing.T) {
	existing := map[string]peer{
		"PRIVATE-KEY-DO-NOT-LOG": {email: "secret@example.invalid", key: "PRIVATE-KEY-DO-NOT-LOG", ips: []string{"198.18.31.2/32"}},
	}
	target := map[string]peer{
		"PRIVATE-KEY-DO-NOT-LOG": {email: "secret@example.invalid", key: "PRIVATE-KEY-DO-NOT-LOG", ips: []string{"198.18.31.3/32"}},
		"SECOND-SECRET-KEY":      {email: "other@example.invalid", key: "SECOND-SECRET-KEY", ips: []string{"198.18.31.4/32"}},
	}
	delta := summarizePeerChanges(existing, target)
	got := awgPeerChangeLine(delta)
	if !strings.Contains(got, "added=1") || !strings.Contains(got, "updated=1") || !strings.Contains(got, "removed=0") || !strings.Contains(got, "total=2") {
		t.Fatalf("missing safe counts: %q", got)
	}
	for _, secret := range []string{"PRIVATE-KEY-DO-NOT-LOG", "SECOND-SECRET-KEY", "secret@example.invalid", "other@example.invalid"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret leaked in event line: %q", got)
		}
	}
}

func failedRecoveryLogOutput(t *testing.T) string {
	t.Helper()
	c := parseConfigMap(t, configMap(t))
	u := testUser(t, "101", "198.18.31.2/32")
	a := newBackend(c, func(c *Config) (*Manager, error) {
		d := fake(c)
		d.failRead = true
		return &Manager{dev: d}, nil
	})
	a.contained = true
	if err := a.SyncUsers(context.Background(), []*common.User{u}); err == nil {
		t.Fatal("expected failed recovery")
	}
	var logs []string
	for {
		select {
		case line := <-a.Logs():
			logs = append(logs, line)
		default:
			return strings.Join(logs, "\n")
		}
	}
}

func TestAWGFailedRecoveryDoesNotEmitReEnableSuccess(t *testing.T) {
	logs := failedRecoveryLogOutput(t)
	if strings.Contains(logs, "event=re_enable result=ok") {
		t.Fatalf("failed recovery emitted false success: %s", logs)
	}
}

func TestAWGSnapshotReadFailureEmitsUAPIError(t *testing.T) {
	logs := failedRecoveryLogOutput(t)
	if !strings.Contains(logs, "event=uapi_error result=failed") {
		t.Fatalf("snapshot read failure missing UAPI error event: %s", logs)
	}
}
