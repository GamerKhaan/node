package amneziawg

import (
	"testing"

	nodeconfig "github.com/pasarguard/node/config"
)

func TestAWGHostRoutingHookLifecycle(t *testing.T) {
	c := &Config{InterfaceName: "awg-test0"}
	a := newBackend(c, nil)
	a.nodeConfig = &nodeconfig.Config{WGHostRouting: true}

	applied := 0
	cleaned := 0
	a.hostRoutingFactory = func(cfg *nodeconfig.Config, interfaceName string) func() {
		if cfg != a.nodeConfig {
			t.Fatal("host routing received wrong node config")
		}
		if interfaceName != c.InterfaceName {
			t.Fatalf("host routing received interface %q", interfaceName)
		}
		applied++
		return func() { cleaned++ }
	}

	a.installHostRouting()
	if applied != 1 {
		t.Fatalf("host routing applied %d times, want 1", applied)
	}

	a.cleanupHostRouting()
	a.cleanupHostRouting()
	if cleaned != 1 {
		t.Fatalf("host routing cleanup ran %d times, want 1", cleaned)
	}
}
