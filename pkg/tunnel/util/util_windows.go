//go:build windows
// +build windows

package util

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// AssignAddressToIface assigns the internal IP address to the WireGuard interface in CIDR notation
// on Windows using netsh command
func AssignAddressToIface(iface, addrCIDR string) error {
	// Parse CIDR notation (e.g., "10.1.1.1/32" -> IP: "10.1.1.1", Mask: "255.255.255.255")
	parts := strings.Split(addrCIDR, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid CIDR notation: %s", addrCIDR)
	}

	ipAddr := parts[0]
	cidrPrefix := parts[1]

	// Convert CIDR prefix to netmask
	_, ipNet, err := net.ParseCIDR(addrCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}

	netmask := net.IP(ipNet.Mask).String()

	// Use netsh to configure the interface
	// netsh interface ip set address "Adapter Name" static <IP> <Netmask>
	cmd := exec.Command(
		"netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", iface),
		"static", ipAddr, netmask,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set IP address on interface %s: %w\noutput: %s", iface, err, string(output))
	}

	return nil
}

// AddPeerRoutes adds the allowed IPs of the peer to the routing table on Windows
// using the route command
func AddPeerRoutes(iface string, allowedIPs []net.IPNet) error {
	for _, ipNet := range allowedIPs {
		// Extract network address and prefix length
		maskOnes, maskBits := ipNet.Mask.Size()
		if maskBits == 0 {
			return fmt.Errorf("invalid mask for route: %s", ipNet.String())
		}

		destination := ipNet.IP.String()
		netmask := net.IP(ipNet.Mask).String()

		// Use route add command
		// route add <destination> mask <netmask> <gateway>
		cmd := exec.Command(
			"route", "add", destination, "MASK", netmask, "0.0.0.0", "METRIC", "1",
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			// Check if route already exists (common error on Windows)
			if !strings.Contains(string(output), "The object already exists") {
				return fmt.Errorf("failed to add route %s on interface %s: %w\noutput: %s", 
					ipNet.String(), iface, err, string(output))
			}
		}
	}

	return nil
}
