// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"bytes"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxActivePeers = 256
const maxSnapshotBytes = 4 << 20
const maxSnapshotLine = 4096

type observedPeer struct {
	ips      []string
	value    counters
	endpoint string
	fields   map[string]string
}
type snapshot struct {
	fields map[string]string
	peers  map[string]observedPeer
}

// Parse directly from the official writer, retaining only a bounded partial line
// and admitted structured state. The official Device still allocates its own buffer.
type snapshotWriter struct {
	result snapshot
	total  int
	line   []byte
	key    string
}

func newSnapshotWriter() *snapshotWriter {
	return &snapshotWriter{result: snapshot{fields: map[string]string{}, peers: map[string]observedPeer{}}}
}
func (w *snapshotWriter) Write(p []byte) (int, error) {
	if len(p) > maxSnapshotBytes-w.total {
		return 0, errors.New("AWG snapshot byte limit")
	}
	w.total += len(p)
	count := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			i = len(p)
		}
		if len(w.line)+i > maxSnapshotLine {
			return 0, errors.New("AWG snapshot line limit")
		}
		w.line = append(w.line, p[:i]...)
		if i == len(p) {
			break
		}
		if err := w.parse(string(w.line)); err != nil {
			return 0, err
		}
		w.line = w.line[:0]
		p = p[i+1:]
	}
	return count, nil
}
func validHexKey(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && strings.ToLower(v) == v
}
func number(v string, max int64) (int64, error) {
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil || n < 0 || n > max || strconv.FormatInt(n, 10) != v {
		return 0, errors.New("invalid AWG numeric field")
	}
	return n, nil
}
func (w *snapshotWriter) parse(line string) error {
	k, v, ok := strings.Cut(line, "=")
	if !ok || k == "" {
		return errors.New("malformed AWG snapshot field")
	}
	if k == "public_key" {
		if !validHexKey(v) || v == strings.Repeat("0", 64) {
			return errors.New("invalid AWG observed key")
		}
		if _, ok := w.result.peers[v]; ok {
			return errors.New("duplicate AWG observed key")
		}
		if len(w.result.peers) >= maxActivePeers {
			return errors.New("AWG snapshot peer limit")
		}
		w.key = v
		w.result.peers[v] = observedPeer{fields: map[string]string{}}
		return nil
	}
	if w.key == "" {
		if _, ok := w.result.fields[k]; ok {
			return errors.New("duplicate AWG device field")
		}
		switch {
		case k == "private_key" || k == "header_protection_key":
			if !validHexKey(v) {
				return errors.New("invalid AWG device key")
			}
		case k == "random_trailers" || k == "disable_cookies":
			if v != "0" && v != "1" {
				return errors.New("invalid AWG observed boolean")
			}
		case integerFields[k] || k == "listen_port":
			if _, e := number(v, 65535); e != nil {
				return e
			}
		case k == "fwmark":
			if _, e := number(v, 4294967295); e != nil {
				return e
			}
		case rangeFields[k] > 0:
			if _, _, e := parseRange(v, rangeFields[k]); e != nil {
				return errors.New("invalid AWG observed range")
			}
		default:
			return errors.New("unsupported AWG device snapshot field")
		}
		w.result.fields[k] = v
		return nil
	}
	p := w.result.peers[w.key]
	if k == "allowed_ip" {
		ip, e := netip.ParsePrefix(v)
		if e != nil || ip.Bits() != ip.Addr().BitLen() || ip.String() != v || slices.Contains(p.ips, v) || len(p.ips) >= 2 {
			return errors.New("invalid AWG observed host address")
		}
		p.ips = append(p.ips, v)
	} else {
		if _, ok := p.fields[k]; ok {
			return errors.New("duplicate AWG peer field")
		}
		switch k {
		case "rx_bytes", "tx_bytes":
			n, e := number(v, 1<<63-1)
			if e != nil {
				return e
			}
			if k == "rx_bytes" {
				p.value.rx = n
			} else {
				p.value.tx = n
			}
		case "preshared_key":
			if !validHexKey(v) {
				return errors.New("invalid AWG peer preshared key")
			}
		case "protocol_version":
			if v != "1" {
				return errors.New("invalid AWG protocol version")
			}
		case "last_handshake_time_sec":
			if _, e := number(v, 1<<63-1); e != nil {
				return e
			}
		case "last_handshake_time_nsec":
			if _, e := number(v, 999999999); e != nil {
				return e
			}
		case "persistent_keepalive_interval":
			if _, _, e := parseRange(v, 65535); e != nil {
				return errors.New("invalid AWG keepalive")
			}
		case "endpoint":
			host, _, e := net.SplitHostPort(v)
			if e != nil {
				return errors.New("invalid AWG endpoint")
			}
			if _, e = netip.ParseAddr(host); e != nil {
				return errors.New("invalid AWG endpoint IP")
			}
			p.endpoint = host
		default:
			return errors.New("unsupported AWG peer snapshot field")
		}
		p.fields[k] = v
	}
	w.result.peers[w.key] = p
	return nil
}
func (w *snapshotWriter) finish() (snapshot, error) {
	if len(w.line) != 0 || w.total == 0 {
		return snapshot{}, errors.New("incomplete AWG snapshot")
	}
	for _, k := range []string{"private_key", "random_trailers", "disable_cookies"} {
		if _, ok := w.result.fields[k]; !ok {
			return snapshot{}, errors.New("missing AWG device field")
		}
	}
	for key, p := range w.result.peers {
		for _, k := range []string{"rx_bytes", "tx_bytes", "protocol_version", "preshared_key", "last_handshake_time_sec", "last_handshake_time_nsec"} {
			if _, ok := p.fields[k]; !ok {
				return snapshot{}, errors.New("incomplete AWG peer state")
			}
		}
		sort.Strings(p.ips)
		w.result.peers[key] = p
	}
	return w.result, nil
}
func (m *Manager) Snapshot() (snapshot, error) {
	w := newSnapshotWriter()
	var err error
	watchdog(15*time.Second, func() { err = m.dev.IpcGetOperation(w) })
	if err != nil {
		return snapshot{}, errors.New("official Device observation failed")
	}
	return w.finish()
}
func (s snapshot) verify(c *Config, target map[string]peer) error {
	if s.fields["disable_cookies"] != "0" {
		return errors.New("AWG cookie protection mismatch")
	}
	for _, line := range strings.Split(strings.TrimSpace(c.deviceUAPI), "\n") {
		k, want, _ := strings.Cut(line, "=")
		got := s.fields[k]
		if k == "listen_port" && want == "0" {
			if got == "" {
				return errors.New("AWG bound port missing")
			}
			continue
		}
		if want == "false" {
			want = "0"
		}
		if want == "true" {
			want = "1"
		}
		if got == "" && (integerFields[k] || rangeFields[k] > 0) {
			got = "0"
		}
		if rangeFields[k] > 0 {
			lo, hi, e := parseRange(want, rangeFields[k])
			gl, gh, ge := parseRange(got, rangeFields[k])
			if e != nil || ge != nil || lo != gl || hi != gh {
				return errors.New("AWG configuration range mismatch")
			}
		} else if got != want {
			return errors.New("AWG configuration mismatch")
		}
	}
	if len(s.peers) != len(target) {
		return errors.New("AWG actual peer set mismatch")
	}
	for key, want := range target {
		got, ok := s.peers[key]
		if !ok || !slices.Equal(want.ips, got.ips) {
			return errors.New("AWG actual authorization mismatch")
		}
		psk := c.psk
		if psk == "" {
			psk = strings.Repeat("0", 64)
		}
		if got.fields["preshared_key"] != psk {
			return errors.New("AWG peer configuration mismatch")
		}
	}
	return nil
}
func (m *Manager) Verify(s snapshot, c *Config, target map[string]peer) error {
	if err := s.verify(c, target); err != nil {
		return err
	}
	if m.expected != nil && !maps.Equal(m.expected, s.fields) {
		return errors.New("AWG device settings changed unexpectedly")
	}
	return nil
}
