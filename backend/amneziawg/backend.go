// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"context"
	"errors"
	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
	"log"
	"strings"
	"sync"
	"time"
)

type AmneziaWG struct {
	mu                   sync.Mutex
	config               *Config
	manager              *Manager
	factory              func(*Config) (*Manager, error)
	peers                map[string]peer // Last confirmed authorization; empty after containment.
	desired              map[string]peer // Latest validated intent; never treated as observation.
	pending              map[accountingOwner]counters
	cursors              map[string]runtimeCursor
	nextEpoch            uint64
	tracker              *stats.Tracker
	interfaceStats       *stats.InterfaceCountersTracker
	accountingIncomplete bool
	contained            bool
	stopped              bool
	logs                 chan string
	logsClosed           bool
	cancel               context.CancelFunc
	startTime            time.Time
}

var _ backend.Backend = (*AmneziaWG)(nil)

func newBackend(c *Config, factory func(*Config) (*Manager, error)) *AmneziaWG {
	return &AmneziaWG{config: c, factory: factory, peers: map[string]peer{}, desired: map[string]peer{}, pending: map[accountingOwner]counters{}, cursors: map[string]runtimeCursor{}, tracker: stats.New(), interfaceStats: stats.NewInterfaceCountersTracker(), logs: make(chan string, 32), startTime: time.Now()}
}
func New(c *Config, users []*common.User) (*AmneziaWG, error) {
	target, err := desiredPeers(c, nil, users, true)
	if err != nil {
		return nil, err
	}
	a := newBackend(c, newManager)
	if err = a.admit(target); err != nil {
		return nil, err
	}
	a.manager, err = a.factory(c)
	if err != nil {
		return nil, err
	}
	if err = a.applyLocked(target, true, false); err != nil {
		a.manager.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go a.watch(ctx)
	a.emit("AMNEZIAWG in-process backend started")
	return a, nil
}
func (a *AmneziaWG) emit(s string) {
	log.Print(s)
	if !a.logsClosed {
		select {
		case a.logs <- s:
		default:
		}
	}
}
func (a *AmneziaWG) incomplete() {
	a.accountingIncomplete = true
	a.emit("AWG_ACCOUNTING_INCOMPLETE: known samples retained; unsampled interval unavailable")
}
func (a *AmneziaWG) readyLocked() error {
	if a.stopped || a.contained || !a.manager.Alive() {
		return errors.New("AWG device unavailable; authoritative full resync required")
	}
	return nil
}
func (a *AmneziaWG) Started() bool   { a.mu.Lock(); defer a.mu.Unlock(); return a.readyLocked() == nil }
func (a *AmneziaWG) Version() string { return runtimeVersion }

// RecoveryControl keeps known usage and authoritative full resync reachable even
// while Started correctly reports false. It grants no authorization to peers.
func (a *AmneziaWG) RecoveryControl() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.contained && !a.stopped
}
func (a *AmneziaWG) Logs() <-chan string { return a.logs }

func (a *AmneziaWG) contain() error {
	a.incomplete()
	if a.manager != nil {
		_ = a.manager.Down()
		a.manager.Close()
		select {
		case <-a.manager.dev.Wait():
		default:
			terminalFailure("owned Device closure unverified")
		}
	}
	a.peers = map[string]peer{}
	a.cursors = map[string]runtimeCursor{}
	a.tracker = stats.New()
	a.contained = true
	a.emit("AWG_DEGRADED_CONTAINED: owned traffic denied; fresh full snapshot required")
	return errors.New("AWG_DEGRADED_CONTAINED; accounting may be incomplete; fresh full snapshot required")
}

func (a *AmneziaWG) failedMutation(known map[string]peer) error {
	// Exactly one post-error observation. No replay, rollback or stale restoration.
	if s, e := a.manager.Snapshot(); e == nil {
		_ = a.account(s, known)
	}
	return a.contain()
}

func (a *AmneziaWG) applyLocked(target map[string]peer, full, restart bool) error {
	if a.stopped {
		return errors.New("AWG backend was shut down")
	}
	if err := a.admit(target); err != nil {
		return err
	}
	if a.contained && !full {
		return errors.New("AWG contained: partial mutation refused; full resync required")
	}
	a.desired = target
	if a.contained {
		if len(target) == 0 {
			a.peers = map[string]peer{}
			return nil
		}
		m, err := a.factory(a.config)
		if err != nil {
			return err
		}
		a.manager = m
		a.contained = false
		a.interfaceStats = stats.NewInterfaceCountersTracker()
	}
	if !a.manager.Alive() {
		return a.contain()
	}
	before, err := a.manager.Snapshot()
	if err != nil {
		return a.contain()
	}
	// Empty full sync is an unconditional denial of every actual peer, including
	// peers absent from the confirmed cache. Other operations reject discrepancies.
	empty := full && len(target) == 0
	if !empty {
		if err = a.manager.Verify(before, a.config, a.peers); err != nil {
			return a.contain()
		}
	}
	if err = a.account(before, a.peers); err != nil {
		return a.contain()
	}
	a.reserve(target)
	known := make(map[string]peer, len(a.peers)+len(target))
	for k, p := range a.peers {
		known[k] = p
	}
	for k, p := range target {
		known[k] = p
		if _, ok := before.peers[k]; !ok {
			a.newEpoch(k)
		}
	}
	if empty {
		a.manager.RemoveAll()
	} else {
		body := peersUAPI(a.peers, target, a.config.psk, false)
		if restart {
			configBody := a.config.deviceUAPI
			if a.config.ListenPort == 0 && a.manager.expected != nil {
				configBody = strings.Replace(configBody, "listen_port=0\n", "listen_port="+a.manager.expected["listen_port"]+"\n", 1)
			}
			body = configBody + body
		}
		if body != "" {
			if err = a.manager.Set(body); err != nil {
				return a.failedMutation(known)
			}
		}
	}
	after, err := a.manager.Snapshot()
	if err != nil {
		return a.contain()
	}
	if err = a.manager.Verify(after, a.config, target); err != nil {
		_ = a.account(after, known)
		return a.contain()
	}
	if err = a.account(after, known); err != nil {
		return a.contain()
	}
	if restart {
		if err = a.manager.Down(); err != nil {
			return a.failedMutation(known)
		}
		if err = a.manager.Up(); err != nil {
			return a.failedMutation(known)
		}
		after, err = a.manager.Snapshot()
		if err != nil {
			return a.contain()
		}
		if err = a.manager.Verify(after, a.config, target); err != nil {
			return a.contain()
		}
		if err = a.account(after, known); err != nil {
			return a.contain()
		}
	}
	a.peers = target
	for k := range a.cursors {
		if _, ok := target[k]; !ok {
			delete(a.cursors, k)
			a.tracker.RemoveStats(publicKeyBase64(k))
		}
	}
	a.reserve(target)
	return nil
}

func (a *AmneziaWG) reconcileLocked(ctx context.Context, users []*common.User, full, restart bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := desiredPeers(a.config, a.desired, users, full)
	if err != nil {
		return err
	}
	return a.applyLocked(target, full, restart)
}
func (a *AmneziaWG) Restart() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applyLocked(a.desired, false, true)
}
func (a *AmneziaWG) watch(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			if !a.stopped && !a.contained {
				if a.sampleLocked() != nil {
					_ = a.contain()
				}
			}
			a.mu.Unlock()
		}
	}
}
func (a *AmneziaWG) Shutdown() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return
	}
	if a.cancel != nil {
		a.cancel()
	}
	if a.manager != nil {
		if !a.contained {
			if a.sampleLocked() != nil {
				a.incomplete()
			}
		}
		a.manager.Close()
	}
	a.stopped = true
	a.peers = map[string]peer{}
	a.cursors = map[string]runtimeCursor{}
	a.emit("AMNEZIAWG shutdown complete")
	close(a.logs)
	a.logsClosed = true
}
