package amneziawg

import (
	"context"
	"errors"
	"fmt"
	"github.com/pasarguard/node/common"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeDevice struct {
	fields                   map[string]string
	peers                    map[string]observedPeer
	done                     chan struct{}
	sets, downs, ups, closes int
	failRead                 bool
	failAfterSet             bool
	prefixError              bool
	ignoreEmpty              bool
	entered, release         chan struct{}
}

func fake(c *Config) *fakeDevice {
	d := &fakeDevice{fields: map[string]string{"random_trailers": "0", "disable_cookies": "0"}, peers: map[string]observedPeer{}, done: make(chan struct{})}
	_ = d.IpcSet(c.deviceUAPI)
	d.sets = 0
	return d
}
func (d *fakeDevice) IpcSet(body string) error {
	d.sets++
	if d.entered != nil {
		close(d.entered)
		<-d.release
		d.entered = nil
	}
	key := ""
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			key = v
			if _, ok := d.peers[key]; !ok {
				d.peers[key] = observedPeer{fields: map[string]string{"preshared_key": strings.Repeat("0", 64)}}
			}
		} else if key == "" {
			if v == "true" {
				v = "1"
			}
			if v == "false" {
				v = "0"
			}
			if k == "listen_port" && v == "0" {
				v = "24000"
			}
			d.fields[k] = v
		} else {
			p := d.peers[key]
			switch k {
			case "remove":
				delete(d.peers, key)
			case "replace_allowed_ips":
				p.ips = nil
				d.peers[key] = p
			case "allowed_ip":
				p.ips = append(p.ips, v)
				d.peers[key] = p
			case "preshared_key":
				p.fields[k] = v
				d.peers[key] = p
			}
		}
		if d.prefixError && k == "remove" {
			d.prefixError = false
			return errors.New("injected prefix failure")
		}
	}
	if d.failAfterSet {
		d.failRead = true
	}
	return nil
}
func (d *fakeDevice) IpcGetOperation(w io.Writer) error {
	if d.failRead {
		return errors.New("injected sample failure")
	}
	var b strings.Builder
	for k, v := range d.fields {
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	for k, p := range d.peers {
		fmt.Fprintf(&b, "public_key=%s\npreshared_key=%s\nprotocol_version=1\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\nrx_bytes=%d\ntx_bytes=%d\n", k, p.fields["preshared_key"], p.value.rx, p.value.tx)
		for _, ip := range p.ips {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
	}
	_, e := io.WriteString(w, b.String())
	return e
}
func (d *fakeDevice) Up() error   { d.ups++; return nil }
func (d *fakeDevice) Down() error { d.downs++; return nil }
func (d *fakeDevice) Close() {
	if d.closes == 0 {
		close(d.done)
	}
	d.closes++
}
func (d *fakeDevice) Wait() chan struct{} { return d.done }
func (d *fakeDevice) RemoveAllPeers() {
	if !d.ignoreEmpty {
		d.peers = map[string]observedPeer{}
	}
}

func fixture(t *testing.T) (*AmneziaWG, *fakeDevice, *common.User) {
	t.Helper()
	c := parseConfigMap(t, configMap(t))
	d := fake(c)
	a := newBackend(c, func(c *Config) (*Manager, error) { return &Manager{dev: fake(c)}, nil })
	a.manager = &Manager{dev: d}
	u := testUser(t, "101", "198.18.31.2/32")
	if e := a.SyncUsers(context.Background(), []*common.User{u}); e != nil {
		t.Fatal(e)
	}
	return a, d, u
}
func userKey(u *common.User) string { k, _ := keyHex(u.Proxies.Wireguard.PublicKey); return k }
func setCounters(d *fakeDevice, u *common.User, rx, tx int64) {
	k := userKey(u)
	p := d.peers[k]
	p.value = counters{rx, tx}
	d.peers[k] = p
}
func total(t *testing.T, a *AmneziaWG, name string, reset bool) int64 {
	t.Helper()
	r, e := a.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_UserStat, Name: name, Reset_: reset})
	if e != nil {
		t.Fatal(e)
	}
	n := int64(0)
	for _, s := range r.Stats {
		n += s.Value
	}
	return n
}

func TestN04PrefixFailureContainsAndRequiresFull(t *testing.T) {
	a, d, u := fixture(t)
	setCounters(d, u, 100, 200)
	if total(t, a, u.Email, false) != 300 {
		t.Fatal("initial sample")
	}
	rotated := testUser(t, u.Email, "198.18.31.3/32")
	d.prefixError = true
	if e := a.SyncUser(context.Background(), rotated); e == nil || !strings.Contains(e.Error(), "DEGRADED_CONTAINED") {
		t.Fatal("missing containment error", e)
	}
	if a.Started() || d.closes != 1 || d.downs != 1 {
		t.Fatal("device not contained")
	}
	if total(t, a, u.Email, false) != 300 {
		t.Fatal("known usage lost")
	}
	if e := a.SyncUser(context.Background(), rotated); e == nil {
		t.Fatal("partial resurrection accepted")
	}
	if e := a.SyncUsers(context.Background(), []*common.User{rotated}); e != nil {
		t.Fatal(e)
	}
	if !a.Started() || !a.accountingIncomplete {
		t.Fatal("full recovery or sticky incomplete diagnostic")
	}
	if e := a.SyncUsers(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	if e := a.SyncUsers(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	if len(a.manager.dev.(*fakeDevice).peers) != 0 {
		t.Fatal("latest empty resurrected peer")
	}
}
func TestN04UnknownActualPeerEmptyTwice(t *testing.T) {
	a, d, _ := fixture(t)
	extra := testUser(t, "999", "198.18.31.5/32")
	k := userKey(extra)
	d.peers[k] = observedPeer{ips: []string{"198.18.31.5/32"}, fields: map[string]string{"preshared_key": strings.Repeat("0", 64)}}
	for i := 0; i < 2; i++ {
		if e := a.SyncUsers(context.Background(), nil); e != nil {
			t.Fatal(e)
		}
		if len(d.peers) != 0 {
			t.Fatal("actual unknown peer survived")
		}
	}
}
func TestN04UnknownActualPeerOrdinarySyncContains(t *testing.T) {
	a, d, u := fixture(t)
	extra := testUser(t, "999", "198.18.31.5/32")
	d.peers[userKey(extra)] = observedPeer{ips: []string{"198.18.31.5/32"}, fields: map[string]string{"preshared_key": strings.Repeat("0", 64)}}
	if a.SyncUser(context.Background(), u) == nil || !a.contained || d.closes != 1 {
		t.Fatal("unknown authorization ignored")
	}
}
func TestN04SampleFailureCannotVetoDenial(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint(full), func(t *testing.T) {
			a, d, u := fixture(t)
			setCounters(d, u, 100, 200)
			_ = total(t, a, u.Email, false)
			d.failRead = true
			u.Inbounds = nil
			var e error
			if full {
				e = a.SyncUsers(context.Background(), nil)
			} else {
				e = a.SyncUser(context.Background(), u)
			}
			if e == nil || !a.contained || d.closes != 1 {
				t.Fatal("collection vetoed denial")
			}
			if total(t, a, u.Email, true) != 300 || total(t, a, u.Email, true) != 0 {
				t.Fatal("known contained settlement lost or repeated")
			}
		})
	}
}
func TestN04FalseEmptySuccessRejected(t *testing.T) {
	a, d, _ := fixture(t)
	d.ignoreEmpty = true
	if a.SyncUsers(context.Background(), nil) == nil || d.closes != 1 {
		t.Fatal("unrevoked device returned success")
	}
}
func TestN04PostObservationFailureContains(t *testing.T) {
	a, d, u := fixture(t)
	d.failAfterSet = true
	u.Proxies.Wireguard.PeerIps = []string{"198.18.31.6/32"}
	if a.SyncUser(context.Background(), u) == nil || !a.contained {
		t.Fatal("unverifiable mutation accepted")
	}
}
func TestN05KnownGenerationsAndRetiredSettlement(t *testing.T) {
	a, d, u := fixture(t)
	setCounters(d, u, 100, 200)
	if e := a.SyncUsers(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	if total(t, a, u.Email, false) != 300 {
		t.Fatal("retired sample lost")
	}
	if e := a.SyncUsers(context.Background(), []*common.User{u}); e != nil {
		t.Fatal(e)
	}
	setCounters(d, u, 150, 250)
	if total(t, a, u.Email, false) != 700 || total(t, a, u.Email, false) != 700 {
		t.Fatal("300 + 400 conservation")
	}
	if e := a.Restart(); e != nil {
		t.Fatal(e)
	}
	if total(t, a, u.Email, true) != 700 || total(t, a, u.Email, true) != 0 {
		t.Fatal("restart cursor or settlement")
	}
	if d.downs != 1 || d.ups != 1 {
		t.Fatal("explicit restart Down/Up")
	}
}
func TestN05CrossIdentityReuseRejectedBeforeMutation(t *testing.T) {
	a, d, u := fixture(t)
	v := *u
	v.Email = "202"
	sets := d.sets
	if a.SyncUsers(context.Background(), []*common.User{&v}) == nil || d.sets != sets {
		t.Fatal("active key transferred")
	}
	setCounters(d, u, 100, 200)
	if e := a.SyncUsers(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	if a.SyncUsers(context.Background(), []*common.User{&v}) == nil {
		t.Fatal("unsettled history transferred")
	}
	if total(t, a, u.Email, true) != 300 {
		t.Fatal("wrong-user attribution")
	}
	if e := a.SyncUsers(context.Background(), []*common.User{&v}); e != nil {
		t.Fatal("settled inactive key rejected", e)
	}
	if total(t, a, v.Email, false) != 0 {
		t.Fatal("settled history leaked")
	}
}
func TestN05UnexpectedResetRetainsKnownAndDenies(t *testing.T) {
	a, d, u := fixture(t)
	setCounters(d, u, 100, 200)
	_ = total(t, a, u.Email, false)
	setCounters(d, u, 1, 2)
	if a.SyncUsers(context.Background(), nil) == nil || !a.contained {
		t.Fatal("uncertain generation accepted")
	}
	if total(t, a, u.Email, false) != 300 {
		t.Fatal("invented or lost uncertain bytes")
	}
}
func TestN03StablePartialFullAndLastDuplicate(t *testing.T) {
	a, d, u := fixture(t)
	v := testUser(t, "202", "198.18.31.3/32")
	w := testUser(t, "303", "198.18.31.4/32")
	if e := a.SyncUsers(context.Background(), []*common.User{u, v, w}); e != nil {
		t.Fatal(e)
	}
	setCounters(d, u, 100, 200)
	sets := d.sets
	if e := a.SyncUsers(context.Background(), []*common.User{u, v, w}); e != nil || d.sets != sets {
		t.Fatal("idempotence", e)
	}
	v.Proxies.Wireguard.PeerIps = []string{"198.18.31.8/32"}
	if e := a.UpdateUsers(context.Background(), []*common.User{v}); e != nil {
		t.Fatal(e)
	}
	if len(d.peers) != 3 || total(t, a, u.Email, false) != 300 {
		t.Fatal("untouched peer changed")
	}
	removed := *v
	removed.Inbounds = nil
	if e := a.UpdateUsers(context.Background(), []*common.User{v, &removed}); e != nil {
		t.Fatal(e)
	}
	if _, ok := d.peers[userKey(v)]; ok {
		t.Fatal("last duplicate identity not authoritative")
	}
}
func TestN04SynchronousSetterAndCanceledWaiter(t *testing.T) {
	a, d, u := fixture(t)
	d.entered = make(chan struct{})
	d.release = make(chan struct{})
	entered := d.entered
	u.Proxies.Wireguard.PeerIps = []string{"198.18.31.8/32"}
	done := make(chan error, 1)
	go func() { done <- a.SyncUser(context.Background(), u) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waiter := make(chan error, 1)
	go func() { waiter <- a.SyncUsers(ctx, nil) }()
	select {
	case <-done:
		t.Fatal("setter abandoned before completion")
	case <-time.After(20 * time.Millisecond):
	}
	close(d.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := <-waiter; !errors.Is(e, context.Canceled) {
		t.Fatal("canceled waiter mutated", e)
	}
	if len(d.peers) != 1 {
		t.Fatal("canceled request revoked user")
	}
}
func TestN05ConcurrentReadsSyncAndReset(t *testing.T) {
	a, d, u := fixture(t)
	setCounters(d, u, 100, 200)
	var wg sync.WaitGroup
	var mu sync.Mutex
	settled := int64(0)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%3 == 0 {
				if e := a.SyncUser(context.Background(), u); e != nil {
					t.Error(e)
				}
			} else {
				r, e := a.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_UsersStat, Reset_: i%3 == 1})
				if e != nil {
					t.Error(e)
					return
				}
				if i%3 == 1 {
					mu.Lock()
					for _, s := range r.Stats {
						settled += s.Value
					}
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()
	settled += total(t, a, u.Email, true)
	if settled != 300 {
		t.Fatal("concurrent settlement", settled)
	}
}
func TestN08FullLedgerAllowsRevocation(t *testing.T) {
	a, _, u := fixture(t)
	for i := 1; i < maxAccountingOwners; i++ {
		a.pending[accountingOwner{"retired-" + fmt.Sprint(i), fmt.Sprintf("%064x", i)}] = counters{rx: 1}
	}
	extra := testUser(t, "extra", "198.18.31.3/32")
	if a.SyncUser(context.Background(), extra) == nil {
		t.Fatal("over-capacity admission accepted")
	}
	if e := a.SyncUsers(context.Background(), nil); e != nil {
		t.Fatal("ledger blocked revocation", e)
	}
	if n := len(a.pending); n != maxAccountingOwners-1 {
		t.Fatal("pending eviction", n)
	}
	if total(t, a, u.Email, false) != 0 {
		t.Fatal("invented active usage")
	}
}
func TestN08CounterOverflowPreservesKnown(t *testing.T) {
	a, d, u := fixture(t)
	a.pending[accountingOwner{u.Email, userKey(u)}] = counters{rx: math.MaxInt64}
	setCounters(d, u, 1, 0)
	if a.SyncUsers(context.Background(), nil) == nil || !a.contained {
		t.Fatal("overflow accepted")
	}
	if total(t, a, u.Email, false) != math.MaxInt64 {
		t.Fatal("known counter overflowed")
	}
}
