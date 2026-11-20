//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

var ethernetInterface = regexp.MustCompile("^en[0-9]+$")

const (
	cidrField             = "ip_cidr"
	interfaceAddressField = "interface_address"
)

type lanRoutes struct {
	Rules     []object
	Outbounds []object
}

func isLANInterface(iface net.Interface) bool {
	const required = net.FlagUp | net.FlagBroadcast
	return ethernetInterface.MatchString(iface.Name) && iface.Flags&required == required &&
		iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) == 0
}

// sing-box tests interface_address by prefix overlap. Checking both ends also
// disables a stale rule when the interface moves to a smaller subnet.
func (r *lanRoutes) addInterface(name string, addresses []netip.Prefix) {
	tag := "wgsplit-lan-" + name
	seen := make(map[netip.Prefix]bool)
	for _, address := range addresses {
		prefix := address.Masked()
		first := prefix.Addr()
		if prefix.Bits() <= 0 || prefix.IsSingleIP() || seen[prefix] {
			continue
		}
		isLinkLocalIPv4 := first.Is4() && first.IsLinkLocalUnicast()
		if !first.IsGlobalUnicast() && !isLinkLocalIPv4 {
			continue
		}
		seen[prefix] = true
		last := first.AsSlice()
		for i, mask := range net.CIDRMask(prefix.Bits(), first.BitLen()) {
			last[i] |= ^mask
		}
		r.Rules = append(r.Rules, object{
			"type": "logical", "mode": "and",
			"rules": []object{
				{cidrField: prefix.String(), interfaceAddressField: object{name: first.String()}},
				{interfaceAddressField: object{name: net.IP(last).String()}},
			},
			"action": "route", outboundField: tag,
		})
	}
	if len(seen) > 0 {
		r.Outbounds = append(r.Outbounds, object{"type": directTag, "tag": tag, "bind_interface": name})
	}
}

func lanConfigPath(profile string) string {
	// sing-box merges -c files in argument order, so the saved profile's rules run first.
	return filepath.Join(filepath.Dir(filepath.Dir(profile)), "runtime", "lan.json")
}

func prepareLANConfig(binary, profile string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list LAN interfaces: %w", err)
	}
	var routes lanRoutes
	for _, iface := range interfaces {
		if !isLANInterface(iface) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("list addresses for %s: %w", iface.Name, err)
		}
		var prefixes []netip.Prefix
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return "", fmt.Errorf("parse %s address %s: %w", iface.Name, address, err)
			}
			prefixes = append(prefixes, prefix)
		}
		routes.addInterface(iface.Name, prefixes)
	}
	return routes.save(binary, profile)
}

func (r *lanRoutes) save(binary, profile string) (string, error) {
	path := lanConfigPath(profile)
	if len(r.Rules) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("remove stale LAN routes: %w", err)
		}
		return "", nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("create LAN config directory: %w", err)
	}
	cfg := object{"route": object{"rules": r.Rules}, "outbounds": r.Outbounds}
	if err := writeJSONChecked(path, cfg, func(tmp string) error {
		if output, err := exec.Command(binary, "check", "-c", profile, "-c", tmp).CombinedOutput(); err != nil {
			return fmt.Errorf("validate profile with LAN routes: %w: %s", err, output)
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("save LAN routes: %w", err)
	}
	return path, nil
}
