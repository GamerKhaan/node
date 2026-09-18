package amneziawg

import (
	"encoding/json"
	"fmt"
	"github.com/pasarguard/node/common"
	"strings"
	"testing"
)

func TestN08SnapshotBudgetsAndStructure(t *testing.T) {
	c := parseConfigMap(t, configMap(t))
	d := fake(c)
	var b strings.Builder
	_ = d.IpcGetOperation(&b)
	base := b.String()
	peerText := func(k string) string {
		return fmt.Sprintf("public_key=%s\npreshared_key=%s\nprotocol_version=1\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\nrx_bytes=0\ntx_bytes=0\nallowed_ip=198.18.31.2/32\n", k, strings.Repeat("0", 64))
	}
	good := base + peerText(fmt.Sprintf("%064x", 1))
	tests := map[string]string{
		"duplicate peer":    good + peerText(fmt.Sprintf("%064x", 1)),
		"duplicate counter": good + "rx_bytes=1\n",
		"overflow counter":  strings.Replace(good, "rx_bytes=0", "rx_bytes=9223372036854775808", 1),
		"negative counter":  strings.Replace(good, "rx_bytes=0", "rx_bytes=-1", 1),
		"missing counter":   strings.Replace(good, "rx_bytes=0\n", "", 1),
		"unknown field":     good + "unknown=1\n",
		"incomplete line":   good + "tx",
		"oversized line":    base + strings.Repeat("x", maxSnapshotLine+1) + "\n",
		"nonhost IP":        strings.Replace(good, "198.18.31.2/32", "198.18.31.0/24", 1),
		"duplicate IP":      good + "allowed_ip=198.18.31.2/32\n",
		"three IPs":         good + "allowed_ip=198.18.31.3/32\nallowed_ip=198.18.31.4/32\n",
		"too many bytes":    strings.Repeat("x", maxSnapshotBytes+1),
	}
	var many strings.Builder
	many.WriteString(base)
	for i := 1; i <= 257; i++ {
		many.WriteString(peerText(fmt.Sprintf("%064x", i)))
	}
	tests["257 peers"] = many.String()
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			w := newSnapshotWriter()
			_, e := w.Write([]byte(input))
			if e == nil {
				_, e = w.finish()
			}
			if e == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	w := newSnapshotWriter()
	for _, v := range []byte(good) {
		if _, e := w.Write([]byte{v}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := w.finish(); e != nil {
		t.Fatal("fragmented valid getter", e)
	}
}
func TestN08AdmissionLimits(t *testing.T) {
	if _, e := NewConfig(strings.Repeat(" ", 64<<10+1)); e == nil {
		t.Fatal("oversized config")
	}
	m := configMap(t)
	m["address"] = []string{"198.18.31.1/24", "198.18.32.1/24", "198.18.33.1/24", "198.18.34.1/24", "198.18.35.1/24", "198.18.36.1/24", "198.18.37.1/24", "198.18.38.1/24", "198.18.39.1/24"}
	raw, _ := json.Marshal(m)
	if _, e := NewConfig(string(raw)); e == nil {
		t.Fatal("nine interface prefixes accepted")
	}
	c := parseConfigMap(t, configMap(t))
	users := []*common.User{}
	for i := 0; i < 256; i++ {
		users = append(users, testUser(t, fmt.Sprint(i), fmt.Sprintf("198.18.31.%d/32", i)))
	}
	// A /16 supports 256 distinct non-server host addresses for the admitted map.
	wide := configMap(t)
	wide["address"] = []string{"198.18.0.1/16"}
	c = parseConfigMap(t, wide)
	target, e := desiredPeers(c, nil, users, true)
	if e != nil || len(target) != 256 {
		t.Fatal("256 peer admission", e)
	}
	users = append(users, testUser(t, "extra", "198.18.32.1/32"))
	if _, e = desiredPeers(c, nil, users, true); e == nil {
		t.Fatal("257 peer admission")
	}
	u := testUser(t, "ips", "198.18.31.2/32")
	u.Proxies.Wireguard.PeerIps = []string{"198.18.31.2/32", "198.18.31.3/32", "198.18.31.4/32"}
	if _, e = desiredPeers(c, nil, []*common.User{u}, true); e == nil {
		t.Fatal("IP cardinality")
	}
}
