// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"io"
	"log"
	"os"
	"runtime/debug"
	"time"
)

const RuntimeCommit = "1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1"
const RuntimeModule = "github.com/amnezia-vpn/amneziawg-go/v3"
const RuntimeModuleVersion = "v3.1.20260814"
const RuntimeModuleSum = "h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0="
const runtimeVersion = "amneziawg-go " + RuntimeModuleVersion + " in-process (" + RuntimeCommit + "; " + RuntimeModuleSum + ")"

// Only the backend's serialized owner may use this seam. It is not shared with WG.
type deviceControl interface {
	IpcSet(string) error
	IpcGetOperation(io.Writer) error
	Up() error
	Down() error
	Close()
	Wait() chan struct{}
	RemoveAllPeers()
}

func embeddedModuleVerified() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, m := range info.Deps {
		if m.Path == RuntimeModule {
			return m.Version == RuntimeModuleVersion && m.Sum == RuntimeModuleSum && m.Replace == nil
		}
	}
	return false
}

func terminalFailure(reason string) {
	log.Print("AWG_TERMINAL_FAILURE: " + reason)
	os.Exit(70)
}

// The operation stays synchronous. Expiry ends this process; no worker is abandoned.
func watchdog(limit time.Duration, fn func()) {
	timer := time.AfterFunc(limit, func() { terminalFailure("management watchdog expired") })
	defer timer.Stop()
	fn()
}
