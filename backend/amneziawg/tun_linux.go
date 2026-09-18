// SPDX-License-Identifier: GPL-3.0-only
package amneziawg

import (
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tunHandoff func(int) (tun.Device, string, error)

func openExclusiveFD(name string, ioctl func(int, *unix.Ifreq) error) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("TUN open failed")
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	req, err := unix.NewIfreq(name)
	if err != nil {
		return -1, errors.New("TUN name rejected")
	}
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_TUN_EXCL)
	if err = ioctl(fd, req); err != nil {
		return -1, errors.New("exclusive TUN creation failed")
	}
	ok = true
	return fd, nil
}

func exclusiveTUN(name string, handoff tunHandoff) (tun.Device, netlink.Link, error) {
	if _, err := netlink.LinkByName(name); err == nil {
		return nil, nil, errors.New("refusing existing interface")
	} else {
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return nil, nil, errors.New("interface preflight unavailable")
		}
	}
	fd, err := openExclusiveFD(name, func(fd int, req *unix.Ifreq) error { return unix.IoctlIfreq(fd, unix.TUNSETIFF, req) })
	if err != nil {
		return nil, nil, err
	}
	// The pinned constructor can retain an opaque os.File on error. Never raw-close
	// or retry after invocation: process exit prevents a finalizer closing a reused FD.
	native, actual, err := handoff(fd)
	if err != nil {
		terminalFailure("TUN constructor failed after descriptor handoff")
		panic("terminal failure returned")
	}
	if actual != name {
		native.Close()
		return nil, nil, errors.New("owned TUN name mismatch")
	}
	link, err := netlink.LinkByName(actual)
	if err != nil {
		native.Close()
		return nil, nil, errors.New("owned TUN index unavailable")
	}
	return native, link, nil
}
