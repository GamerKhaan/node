//go:build !linux

package wireguard

import "github.com/pasarguard/node/config"

// applyLinuxHostRouting is a no-op on non-Linux platforms.
// ApplyLinuxHostRouting reuses the WireGuard host-routing policy for any owned tunnel interface.
func ApplyLinuxHostRouting(cfg *config.Config, interfaceName string) func() {
	return applyLinuxHostRouting(cfg, interfaceName)
}

func applyLinuxHostRouting(_ *config.Config, _ string) func() { return nil }
