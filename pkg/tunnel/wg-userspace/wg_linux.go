//go:build linux
// +build linux

package userspacewg

import (
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/yago-123/wg-punch/pkg/tunnel"
)

// ensureTunInterfaceExists creates and brings up a TUN interface on Linux
func (u *userspaceWGTunnel) ensureTunInterfaceExists(iface string) (tun.Device, error) {
	// Try to delete the existing interface (optional safety)
	link, err := netlink.LinkByName(iface)
	if err == nil {
		u.logger.Info("Deleting pre-existing interface", "iface", iface)
		_ = netlink.LinkDel(link) // ignore error — best effort
	}

	// Only proceed if the interface is truly missing
	if !strings.Contains(err.Error(), "Link not found") {
		return nil, fmt.Errorf("error checking interface %s: %w", iface, err)
	}

	// Now create it cleanly
	tunDev, err := tun.CreateTUN(iface, DefaultNetMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface %s: %w", iface, err)
	}

	link, err = netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup interface %s: %w", iface, err)
	}

	// Set the interface up
	if errSetup := netlink.LinkSetUp(link); errSetup != nil {
		return nil, fmt.Errorf("failed to bring interface %s up: %w", iface, errSetup)
	}

	u.logger.Info("Created TUN interface", "iface", iface)
	return tunDev, nil
}
