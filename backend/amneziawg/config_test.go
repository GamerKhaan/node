// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"encoding/hex"
	"encoding/json"
	"github.com/pasarguard/node/common"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"strings"
	"testing"
)

func nonCanonicalPrivateKey() wgtypes.Key {
	var key wgtypes.Key
	for i := range key {
		key[i] = byte(i + 1)
	}
	key[0] |= 7
	key[31] |= 128
	return key
}

func TestRC3PrivateKeyUsesOfficialEffectiveScalar(t *testing.T) {
	key := nonCanonicalPrivateKey()
	m := configMap(t)
	m["private_key"] = key.String()
	c := parseConfigMap(t, m)

	effective := key
	effective[0] &= 248
	effective[31] = (effective[31] & 127) | 64
	want := "private_key=" + hex.EncodeToString(effective[:]) + "\n"
	if !strings.Contains(c.deviceUAPI, want) {
		t.Fatal("node did not use the official effective private scalar")
	}
}

func configMap(t *testing.T) map[string]any {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"interface_name": "awgp1s", "private_key": key.String(), "listen_port": 0, "address": []string{"198.18.31.1/24"}, "awg": map[string]any{"jc": 0, "random_trailers": false, "disable_cookies": false, "content_padding_addition": "0-16"}}
}
func parseConfigMap(t *testing.T, m map[string]any) *Config {
	t.Helper()
	b, _ := json.Marshal(m)
	c, e := NewConfig(string(b))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestConfigPreservesZeroFalseAndRange(t *testing.T) {
	c := parseConfigMap(t, configMap(t))
	for _, s := range []string{"jc=0\n", "random_trailers=false\n", "disable_cookies=false\n", "listen_port=0\n", "content_padding_addition=0-16\n"} {
		if !strings.Contains(c.deviceUAPI, s) {
			t.Fatalf("missing %s", s)
		}
	}
}
func TestConfigRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name string
		edit func(map[string]any)
	}{
		{"interface path", func(m map[string]any) { m["interface_name"] = "../wg0" }},
		{"unknown field", func(m map[string]any) { m["runtime_command"] = "other" }},
		{"cookie disable", func(m map[string]any) { m["awg"].(map[string]any)["disable_cookies"] = true }},
		{"string boolean", func(m map[string]any) { m["awg"].(map[string]any)["random_trailers"] = "false" }},
		{"null boolean", func(m map[string]any) { m["awg"].(map[string]any)["random_trailers"] = nil }},
		{"reverse range", func(m map[string]any) { m["awg"].(map[string]any)["h1"] = "42-3" }},
		{"overlapping headers", func(m map[string]any) { m["awg"].(map[string]any)["h1"] = "2-10" }},
		{"missing padding", func(m map[string]any) { m["awg"].(map[string]any)["header_protection_key"] = m["private_key"] }},
		{"newline injection", func(m map[string]any) { m["awg"].(map[string]any)["h1"] = "5\nprivate_key=x" }},
		{"negative junk", func(m map[string]any) { m["awg"].(map[string]any)["jc"] = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := configMap(t)
			test.edit(m)
			b, _ := json.Marshal(m)
			if _, e := NewConfig(string(b)); e == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func testUser(t *testing.T, email, ip string) *common.User {
	t.Helper()
	key, e := wgtypes.GeneratePrivateKey()
	if e != nil {
		t.Fatal(e)
	}
	return &common.User{Email: email, Inbounds: []string{"awgp1s"}, Proxies: &common.Proxy{Wireguard: &common.Wireguard{PublicKey: key.PublicKey().String(), PeerIps: []string{ip}}}}
}
func TestPeerReconciliationOwnershipAndRevocation(t *testing.T) {
	c := parseConfigMap(t, configMap(t))
	u := testUser(t, "one", "198.18.31.2/32")
	v := testUser(t, "two", "198.18.31.3/32")
	original, e := desiredPeers(c, nil, []*common.User{u, v}, true)
	if e != nil {
		t.Fatal(e)
	}
	same, e := desiredPeers(c, original, []*common.User{u}, false)
	if e != nil || len(same) != 2 {
		t.Fatal("partial update lost an untouched peer")
	}
	if peersUAPI(original, same, "", false) != "" {
		t.Fatal("idempotent sync mutates runtime")
	}
	u.Inbounds = nil
	removed, e := desiredPeers(c, original, []*common.User{u}, false)
	if e != nil || len(removed) != 1 {
		t.Fatal("inbound removal failed")
	}
	empty, e := desiredPeers(c, original, nil, true)
	if e != nil || len(empty) != 0 {
		t.Fatal("empty full snapshot is not authoritative")
	}
	if !strings.Contains(peersUAPI(original, removed, "", false), "remove=true") {
		t.Fatal("missing actual device revocation")
	}
	v.Proxies.Wireguard.PeerIps = []string{"198.18.31.2/32"}
	u.Inbounds = []string{"awgp1s"}
	if _, e := desiredPeers(c, nil, []*common.User{u, v}, true); e == nil {
		t.Fatal("duplicate IP accepted")
	}
	v.Proxies.Wireguard.PeerIps = []string{"198.18.31.3/32"}
	v.Proxies.Wireguard.PublicKey = u.Proxies.Wireguard.PublicKey
	if _, e := desiredPeers(c, original, []*common.User{v}, false); e == nil {
		t.Fatal("untouched identity key stolen")
	}
}

func TestRejectServerPublicKeyAsPeer(t *testing.T) {
	c := parseConfigMap(t, configMap(t))
	u := testUser(t, "self-peer", "198.18.31.2/32")
	private, err := wgtypes.ParseKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	u.Proxies.Wireguard.PublicKey = private.PublicKey().String()
	for _, full := range []bool{true, false} {
		_, err := desiredPeers(c, nil, []*common.User{u}, full)
		if err == nil || !strings.Contains(err.Error(), "server public key") {
			t.Fatal("server key requires explicit validation error", err)
		}
	}
}
