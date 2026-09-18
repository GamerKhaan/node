package amneziawg

import (
	"bufio"
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRC3NonCanonicalPrivateKeyReadback(t *testing.T) {
	nativeRequired(t)
	key := nonCanonicalPrivateKey()
	m := configMap(t)
	m["interface_name"] = "rc3key"
	m["private_key"] = key.String()
	c := parseConfigMap(t, m)
	mgr, err := createManager(c)
	if mgr != nil {
		defer mgr.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func nativeRequired(t *testing.T) {
	t.Helper()
	if os.Getenv("M1_TUN_TESTS") != "1" {
		t.Skip("Requires exact-owned Linux M1 TUN test container; mandatory in final gate")
	}
}
func assertAbsent(t *testing.T, name string) {
	t.Helper()
	_, e := netlink.LinkByName(name)
	var missing netlink.LinkNotFoundError
	if !errors.As(e, &missing) {
		t.Fatal("owned TUN not released", e)
	}
}
func TestN06NativeLifecycleAndCollision(t *testing.T) {
	nativeRequired(t)
	c := parseConfigMap(t, configMap(t))
	m, e := createManager(c)
	if e != nil {
		t.Fatal(e)
	}
	index := m.link.Attrs().Index
	if _, e := createManager(c); e == nil {
		t.Fatal("adopted existing TUN")
	}
	link, e := netlink.LinkByName(c.InterfaceName)
	if e != nil || link.Attrs().Index != index {
		t.Fatal("collision altered owner")
	}
	s, e := m.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Verify(s, c, map[string]peer{}); e != nil {
		t.Fatal(e)
	}
	if e = m.Down(); e != nil {
		t.Fatal(e)
	}
	if e = m.Up(); e != nil {
		t.Fatal(e)
	}
	m.Close()
	m.Close()
	assertAbsent(t, c.InterfaceName)
	m, e = createManager(c)
	if e != nil {
		t.Fatal("recreate", e)
	}
	m.Close()
	assertAbsent(t, c.InterfaceName)
}
func TestN06PreHandoffFDRollback(t *testing.T) {
	nativeRequired(t)
	captured := -1
	_, e := openExclusiveFD("m1rollback", func(fd int, _ *unix.Ifreq) error { captured = fd; return errors.New("injected ioctl failure") })
	if e == nil || captured < 0 {
		t.Fatal("fixture did not reach pre-handoff failure")
	}
	if _, e = unix.FcntlInt(uintptr(captured), unix.F_GETFD, 0); !errors.Is(e, unix.EBADF) {
		t.Fatal("pre-handoff descriptor leaked", e)
	}
	assertAbsent(t, "m1rollback")
}
func TestN06TUNReadFailurePropagatesWait(t *testing.T) {
	nativeRequired(t)
	native, _, e := exclusiveTUN("m1readfail", tun.CreateUnmonitoredTUNFromFD)
	if e != nil {
		t.Fatal(e)
	}
	d := device.NewDevice(native, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if e = d.Up(); e != nil {
		t.Fatal(e)
	}
	native.Close()
	select {
	case <-d.Wait():
	case <-time.After(5 * time.Second):
		t.Fatal("TUN failure did not close Device")
	}
	d.Close()
	assertAbsent(t, "m1readfail")
}
func TestN06TerminalHelper(t *testing.T) {
	mode := os.Getenv("M1_TERMINAL_HELPER")
	if mode == "" {
		return
	}
	if mode == "handoff" {
		_, _, _ = exclusiveTUN("m1terminal", func(fd int) (tun.Device, string, error) {
			// Establish the official constructor's ownership before injecting an opaque
			// constructor return failure. The adapter must exit, never raw-close/retry.
			_, _, e := tun.CreateUnmonitoredTUNFromFD(fd)
			if e != nil {
				return nil, "", e
			}
			return nil, "", errors.New("injected post-handoff error")
		})
		t.Fatal("terminal constructor path returned")
	}
	c := parseConfigMap(t, configMap(t))
	c.InterfaceName = "m1terminal"
	m, e := createManager(c)
	if e != nil {
		t.Fatal(e)
	}
	_ = m
	if mode == "watchdog" {
		watchdog(20*time.Millisecond, func() { select {} })
		t.Fatal("watchdog returned")
	}
	if mode == "kill" {
		os.Stdout.WriteString("M1_CHILD_READY\n")
		select {}
	}
}
func TestN06TerminalPoliciesReleaseOwnedTUN(t *testing.T) {
	nativeRequired(t)
	for _, mode := range []string{"handoff", "watchdog", "kill"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestN06TerminalHelper$")
			cmd.Env = append(os.Environ(), "M1_TERMINAL_HELPER="+mode)
			if mode == "kill" {
				stdout, e := cmd.StdoutPipe()
				if e != nil {
					t.Fatal(e)
				}
				if e = cmd.Start(); e != nil {
					t.Fatal(e)
				}
				ready := make(chan bool, 1)
				go func() {
					s := bufio.NewScanner(stdout)
					for s.Scan() {
						if strings.Contains(s.Text(), "M1_CHILD_READY") {
							ready <- true
							return
						}
					}
					ready <- false
				}()
				select {
				case ok := <-ready:
					if !ok {
						t.Fatal("helper failed before ready")
					}
				case <-time.After(10 * time.Second):
					cmd.Process.Kill()
					cmd.Wait()
					t.Fatal("helper readiness timeout")
				}
				if e = cmd.Process.Kill(); e != nil {
					t.Fatal(e)
				}
				if e = cmd.Wait(); e == nil {
					t.Fatal("killed child reported success")
				}
			} else {
				e := cmd.Run()
				var exited *exec.ExitError
				if !errors.As(e, &exited) || exited.ExitCode() != 70 {
					t.Fatal("terminal failure did not exit 70", e)
				}
			}
			assertAbsent(t, "m1terminal")
		})
	}
}
