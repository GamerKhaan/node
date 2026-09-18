// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"context"
	"errors"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
	"runtime"
	"time"
)

func (a *AmneziaWG) sampleLocked() error {
	if err := a.readyLocked(); err != nil {
		return err
	}
	s, err := a.manager.Snapshot()
	if err != nil {
		return err
	}
	if err = a.manager.Verify(s, a.config, a.peers); err != nil {
		return err
	}
	return a.account(s, a.peers)
}
func (a *AmneziaWG) GetStats(ctx context.Context, r *common.StatRequest) (*common.StatResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !a.stopped && !a.contained {
		if a.sampleLocked() != nil {
			_ = a.contain()
		}
	}
	if a.accountingIncomplete {
		a.emit("AWG_ACCOUNTING_INCOMPLETE: returning only known attributable samples")
	}
	switch r.GetType() {
	case common.StatType_UsersStat:
		return a.accountingStats("", true, r.GetReset_()), nil
	case common.StatType_UserStat:
		return a.accountingStats(r.GetName(), false, r.GetReset_()), nil
	case common.StatType_Outbound, common.StatType_Outbounds:
		if err := a.readyLocked(); err != nil {
			return nil, err
		}
		rx, tx, err := a.manager.GetInterfaceStats()
		if err != nil {
			return nil, err
		}
		rx, tx = a.interfaceStats.Delta(rx, tx, r.GetReset_())
		name := r.GetName()
		if name == "" {
			name = a.config.InterfaceName
		}
		return &common.StatResponse{Stats: stats.BuildInterfaceStats(name, "interface", rx, tx)}, nil
	default:
		return nil, errors.New("unsupported AWG statistics type")
	}
}
func (a *AmneziaWG) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.readyLocked(); err != nil {
		return nil, err
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &common.BackendStatsResponse{NumGoroutine: uint32(runtime.NumGoroutine()), NumGc: m.NumGC, Alloc: m.Alloc, TotalAlloc: m.TotalAlloc, Sys: m.Sys, Mallocs: m.Mallocs, Frees: m.Frees, LiveObjects: m.Mallocs - m.Frees, PauseTotalNs: m.PauseTotalNs, Uptime: uint32(time.Since(a.startTime).Seconds())}, nil
}
func (a *AmneziaWG) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, errors.New("AWG latency probes are outside M1")
}
func (a *AmneziaWG) onlineKeys(ctx context.Context, email string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.sampleLocked(); err != nil {
		if !a.contained && !a.stopped {
			_ = a.contain()
		}
		return nil, err
	}
	keys := []string{}
	for k, p := range a.peers {
		if p.email == email {
			keys = append(keys, publicKeyBase64(k))
		}
	}
	return keys, nil
}
func (a *AmneziaWG) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys, err := a.onlineKeys(ctx, email)
	if err != nil {
		return nil, err
	}
	r := &common.OnlineStatResponse{Name: email}
	if a.tracker.AnyActiveSince(keys, time.Now().Add(-45*time.Second)) {
		r.Value = 1
	}
	return r, nil
}
func (a *AmneziaWG) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys, err := a.onlineKeys(ctx, email)
	if err != nil {
		return nil, err
	}
	return &common.StatsOnlineIpListResponse{Name: email, Ips: a.tracker.EndpointActivity(keys)}, nil
}
