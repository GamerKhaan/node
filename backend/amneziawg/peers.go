// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"

	"github.com/pasarguard/node/common"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peer struct {
	email, key string
	ips        []string
}

// desiredPeers follows upstream full-snapshot versus touched-email reconciliation.
// Invalid supplied credentials fail the request before any device mutation.
// The reused Wireguard message is only a public-key/IP carrier, not backend dispatch.
func desiredPeers(c *Config, existing map[string]peer, users []*common.User, full bool) (map[string]peer, error) {
	if len(users) > maxAccountingOwners {
		return nil, errors.New("AWG input user cardinality limit")
	}
	target := map[string]peer{}
	if !full {
		for key, p := range existing {
			target[key] = p
		}
	}
	last := map[string]*common.User{}
	for _, u := range users {
		if u == nil || u.GetEmail() == "" || len(u.GetEmail()) > 256 {
			return nil, errors.New("AWG user requires an identity")
		}
		last[u.GetEmail()] = u
	}
	for key, p := range target {
		if _, touched := last[p.email]; touched {
			delete(target, key)
		}
	}
	for _, u := range last {
		if !slices.Contains(u.GetInbounds(), c.InterfaceName) {
			continue
		}
		credential := u.GetProxies().GetWireguard()
		key, err := keyHex(credential.GetPublicKey())
		if err != nil {
			return nil, errors.New("AWG peer public key is invalid")
		}
		if key == c.publicKey {
			return nil, errors.New("AWG peer public key must not equal the server public key")
		}
		if len(credential.GetPeerIps()) > 2 {
			return nil, errors.New("AWG peer address cardinality limit")
		}
		p := peer{email: u.GetEmail(), key: key}
		for _, s := range credential.GetPeerIps() {
			ip, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, errors.New("AWG peer IP must be a host CIDR")
			}
			ones, bits := n.Mask.Size()
			if ones != bits {
				return nil, errors.New("AWG Phase 1 peers require /32 or /128 host addresses")
			}
			for _, address := range c.Address {
				serverIP, _, _ := net.ParseCIDR(address)
				if serverIP.Equal(ip) {
					return nil, errors.New("AWG peer must not claim a server address")
				}
			}
			allowed := false
			for _, pool := range c.networks {
				if pool.Contains(ip) {
					allowed = true
					break
				}
			}
			if allowed {
				p.ips = append(p.ips, n.String())
			}
		}
		if len(p.ips) == 0 {
			continue
		}
		sort.Strings(p.ips)
		p.ips = slices.Compact(p.ips)
		if previous, ok := target[key]; ok && previous.email != p.email {
			return nil, errors.New("AWG peer key belongs to another identity")
		}
		target[key] = p
	}
	ips := map[string]string{}
	for _, p := range target {
		for _, ip := range p.ips {
			if owner, ok := ips[ip]; ok && owner != p.email {
				return nil, errors.New("duplicate AWG peer address")
			}
			ips[ip] = p.email
		}
	}
	if len(target) > maxActivePeers {
		return nil, errors.New("AWG active peer admission limit")
	}
	return target, nil
}

func peersUAPI(existing, target map[string]peer, psk string, force bool) string {
	var b strings.Builder
	keys := make([]string, 0, len(existing))
	for k := range existing {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := target[key]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", key)
		}
	}
	keys = keys[:0]
	for k := range target {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := target[key]
		old, ok := existing[key]
		if !force && ok && slices.Equal(old.ips, p.ips) {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\npersistent_keepalive_interval=0\n", key)
		if psk != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		for _, ip := range p.ips {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
	}
	return b.String()
}

func publicKeyBase64(raw string) string {
	value, _ := hex.DecodeString(raw)
	var key wgtypes.Key
	copy(key[:], value)
	return key.String()
}
func (a *AmneziaWG) SyncUser(ctx context.Context, u *common.User) error {
	return a.UpdateUsers(ctx, []*common.User{u})
}
func (a *AmneziaWG) SyncUsers(ctx context.Context, users []*common.User) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcileLocked(ctx, users, true, false)
}
func (a *AmneziaWG) UpdateUsers(ctx context.Context, users []*common.User) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcileLocked(ctx, users, false, false)
}
func (a *AmneziaWG) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcileLocked(ctx, users, false, true)
}
