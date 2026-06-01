//go:build windows
// +build windows

package userspacewg

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// ensureTunInterfaceExists creates and brings up a TUN interface on Windows
// Uses the Wintun driver which is cross-platform compatible
func (u *userspaceWGTunnel) ensureTunInterfaceExists(iface string) (tun.Device, error) {
	u.logger.Info("Creating TUN interface on Windows", "iface", iface)

	// Create the TUN device
	// On Windows, tun.CreateTUN uses Wintun driver automatically
	tunDev, err := tun.CreateTUN(iface, DefaultNetMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface %s: %w", iface, err)
	}

	// Try to bring up the interface using netsh
	// Note: The interface might not be available immediately via netsh after creation
	cmd := exec.Command("netsh", "interface", "set", "interface", "name="+iface, "admin=enabled")
	if output, err := cmd.CombinedOutput(); err != nil {
		u.logger.Info("Warning: could not enable interface via netsh", "error", err, "output", string(output))
		// This is not fatal - the interface should still work
	}

	u.logger.Info("Created TUN interface on Windows", "iface", iface)
	return tunDev, nil
}
