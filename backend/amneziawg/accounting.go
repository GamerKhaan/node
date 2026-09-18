// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"errors"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
	"math"
)

const maxAccountingOwners = 4096

type accountingOwner struct{ email, key string }
type counters struct{ rx, tx int64 }
type runtimeCursor struct {
	epoch uint64
	value counters
}

func (a *AmneziaWG) admit(target map[string]peer) error {
	if len(target) > maxActivePeers {
		return errors.New("AWG active peer admission limit")
	}
	count := len(a.pending)
	for key, p := range target {
		if old, ok := a.peers[key]; ok && old.email != p.email {
			return errors.New("AWG active key belongs to another identity")
		}
		for owner, v := range a.pending {
			if owner.key == key && owner.email != p.email && v != (counters{}) {
				return errors.New("AWG key has another identity's unsettled history")
			}
		}
		if _, ok := a.pending[accountingOwner{p.email, key}]; !ok {
			count++
		}
	}
	for owner, v := range a.pending {
		p, ok := target[owner.key]
		if v == (counters{}) && (!ok || p.email != owner.email) {
			count--
		}
	}
	if count > maxAccountingOwners {
		return errors.New("AWG pending ledger admission limit")
	}
	return nil
}
func (a *AmneziaWG) reserve(target map[string]peer) {
	for owner, v := range a.pending {
		p, ok := target[owner.key]
		if v == (counters{}) && (!ok || p.email != owner.email) {
			delete(a.pending, owner)
		}
	}
	for k, p := range target {
		o := accountingOwner{p.email, k}
		if _, ok := a.pending[o]; !ok {
			a.pending[o] = counters{}
		}
	}
}
func (a *AmneziaWG) newEpoch(key string) {
	if a.nextEpoch == math.MaxUint64 {
		terminalFailure("counter generation exhausted")
	}
	a.nextEpoch++
	a.cursors[key] = runtimeCursor{epoch: a.nextEpoch}
}
func checkedAdd(x, y int64) (int64, error) {
	if x < 0 || y < 0 || x > math.MaxInt64-y {
		return 0, errors.New("AWG accounting overflow")
	}
	return x + y, nil
}

// Stage the entire known sample before publishing any value or cursor.
func (a *AmneziaWG) account(s snapshot, owners map[string]peer) error {
	next := make(map[accountingOwner]counters, len(a.pending))
	for k, v := range a.pending {
		next[k] = v
	}
	cursors := make(map[string]runtimeCursor, len(a.cursors))
	for k, v := range a.cursors {
		cursors[k] = v
	}
	for k, p := range owners {
		observed, ok := s.peers[k]
		if !ok {
			continue
		}
		cur, known := cursors[k]
		if !known {
			return errors.New("AWG unknown counter generation")
		}
		v := observed.value
		if v.rx < cur.value.rx || v.tx < cur.value.tx {
			return errors.New("AWG counter generation uncertain")
		}
		owner := accountingOwner{p.email, k}
		old := next[owner]
		rx, e := checkedAdd(old.rx, v.rx-cur.value.rx)
		if e != nil {
			return e
		}
		tx, e := checkedAdd(old.tx, v.tx-cur.value.tx)
		if e != nil {
			return e
		}
		next[owner] = counters{rx, tx}
		cur.value = v
		cursors[k] = cur
	}
	if len(next) > maxAccountingOwners {
		return errors.New("AWG observed ledger cardinality overflow")
	}
	total := int64(0)
	for _, v := range next {
		var e error
		total, e = checkedAdd(total, v.rx)
		if e != nil {
			return e
		}
		total, e = checkedAdd(total, v.tx)
		if e != nil {
			return e
		}
	}
	a.pending = next
	a.cursors = cursors
	samples := []stats.Sample{}
	for k, p := range owners {
		if v, ok := s.peers[k]; ok {
			samples = append(samples, stats.Sample{PublicKey: publicKeyBase64(k), Email: p.email, Rx: v.value.rx, Tx: v.value.tx, EndpointIP: v.endpoint})
		}
	}
	a.tracker.UpdateStatsBatch(samples)
	return nil
}
func (a *AmneziaWG) accountingStats(name string, all, reset bool) *common.StatResponse {
	r := &common.StatResponse{}
	for owner, v := range a.pending {
		if !all && name != owner.email {
			continue
		}
		r.Stats = append(r.Stats, stats.BuildInterfaceStats(owner.email, publicKeyBase64(owner.key), v.rx, v.tx)...)
		if reset {
			a.pending[owner] = counters{}
		}
	}
	a.reserve(a.peers)
	return r
}
