// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"
	"math"
	"time"
)

// Manager owns one official Device and its exclusively created, nonpersistent TUN.
// Every method is called by the same backend lock; no socket/daemon exists here.
type Manager struct {
	dev      deviceControl
	link     netlink.Link
	closed   bool
	expected map[string]string
}

func newManager(c *Config) (m *Manager, err error) {
	if !embeddedModuleVerified() {
		return nil, errors.New("official embedded AWG module provenance mismatch")
	}
	watchdog(15*time.Second, func() { m, err = createManager(c) })
	return
}

func createManager(c *Config) (*Manager, error) {
	native, link, err := exclusiveTUN(c.InterfaceName, tun.CreateUnmonitoredTUNFromFD)
	if err != nil {
		return nil, err
	}
	m := &Manager{link: link}
	// Official logging can contain configuration details. Only sanitized adapter
	// diagnostics are emitted; the official logger is disabled.
	m.dev = device.NewDevice(native, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	ok := false
	defer func() {
		if !ok {
			m.Close()
		}
	}()
	for _, s := range c.Address {
		address, e := netlink.ParseAddr(s)
		if e != nil {
			return nil, errors.New("owned TUN address rejected")
		}
		if e = netlink.AddrAdd(link, address); e != nil {
			return nil, errors.New("owned TUN address setup failed")
		}
	}
	if err = netlink.LinkSetMTU(link, 1280); err != nil {
		return nil, errors.New("owned TUN MTU setup failed")
	}
	if err = m.Set(c.deviceUAPI); err != nil {
		return nil, err
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return nil, errors.New("owned TUN link up failed")
	}
	if err = m.Up(); err != nil {
		return nil, err
	}
	snap, err := m.Snapshot()
	if err != nil {
		return nil, err
	}
	if err = snap.verify(c, map[string]peer{}); err != nil {
		return nil, err
	}
	m.expected = snap.fields
	ok = true
	return m, nil
}

func (m *Manager) Alive() bool {
	if m == nil || m.closed || m.dev == nil {
		return false
	}
	select {
	case <-m.dev.Wait():
		return false
	default:
		return true
	}
}
func (m *Manager) Set(body string) (err error) {
	watchdog(15*time.Second, func() { err = m.dev.IpcSet(body) })
	if err != nil {
		return errors.New("official Device mutation failed")
	}
	return nil
}
func (m *Manager) Up() (err error) {
	watchdog(15*time.Second, func() { err = m.dev.Up() })
	if err != nil {
		return errors.New("official Device Up failed")
	}
	return nil
}
func (m *Manager) Down() (err error) {
	watchdog(5*time.Second, func() { err = m.dev.Down() })
	if err != nil {
		return errors.New("official Device Down failed")
	}
	return nil
}
func (m *Manager) RemoveAll() { watchdog(15*time.Second, m.dev.RemoveAllPeers) }
func (m *Manager) Close() {
	if m == nil || m.closed {
		return
	}
	watchdog(5*time.Second, m.dev.Close)
	m.closed = true
}
func (m *Manager) GetInterfaceStats() (int64, int64, error) {
	if !m.Alive() || m.link == nil {
		return 0, 0, errors.New("owned TUN unavailable")
	}
	link, err := netlink.LinkByIndex(m.link.Attrs().Index)
	if err != nil || link.Attrs().Name != m.link.Attrs().Name || link.Type() != m.link.Type() {
		return 0, 0, errors.New("owned TUN identity unavailable")
	}
	s := link.Attrs().Statistics
	if s == nil || s.RxBytes > math.MaxInt64 || s.TxBytes > math.MaxInt64 {
		return 0, 0, errors.New("invalid owned TUN counters")
	}
	return int64(s.RxBytes), int64(s.TxBytes), nil
}
