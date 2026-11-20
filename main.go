//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type object = map[string]any
type rule struct {
	Domains []string `json:"domain_suffix"`
}
type bypassList struct {
	Version int    `json:"version"`
	Rules   []rule `json:"rules"`
}

const (
	listVersion   = 3
	tunnelTag     = "wg"
	directTag     = "direct"
	bypassTag     = "bypass"
	localResolver = "local-dns"
	outboundField = "outbound"
)

// Keys wg-quick writes that wgsplit understands, and the section each belongs
// to. wireguard-tools matches sections and keys case-insensitively, so the
// lookup is keyed on the lower-cased spelling.
var profileKeys = map[string]struct{ canonical, section string }{
	"privatekey":          {"PrivateKey", "Interface"},
	"address":             {"Address", "Interface"},
	"dns":                 {"DNS", "Interface"},
	"mtu":                 {"MTU", "Interface"},
	"publickey":           {"PublicKey", "Peer"},
	"presharedkey":        {"PresharedKey", "Peer"},
	"endpoint":            {"Endpoint", "Peer"},
	"allowedips":          {"AllowedIPs", "Peer"},
	"persistentkeepalive": {"PersistentKeepalive", "Peer"},
}

var repeatable = map[string]bool{"Address": true, "DNS": true, "AllowedIPs": true}

func parse(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fields := map[string]string{}
	seen := map[string]bool{}
	section := ""
	s := bufio.NewScanner(f)
	for n := 1; s.Scan(); n++ {
		line := s.Text()
		if n == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			switch {
			case strings.EqualFold(name, "Interface"):
				section = "Interface"
			case strings.EqualFold(name, "Peer"):
				section = "Peer"
			default:
				return nil, fmt.Errorf("%s: unsupported section %q at line %d (expected [Interface] or [Peer])", path, name, n)
			}
			if seen[section] {
				return nil, fmt.Errorf("%s: repeated [%s] section at line %d (one peer supported)", path, section, n)
			}
			seen[section] = true
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s: malformed line %d (expected Key = Value)", path, n)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if section == "" {
			return nil, fmt.Errorf("%s: %q at line %d comes before any [Interface] or [Peer] section", path, k, n)
		}
		key, known := profileKeys[strings.ToLower(k)]
		if !known {
			return nil, fmt.Errorf("%s: unsupported key %q at line %d", path, k, n)
		}
		if key.section != section {
			return nil, fmt.Errorf("%s: %s belongs in [%s] but appears in [%s] at line %d", path, key.canonical, key.section, section, n)
		}
		if v == "" {
			return nil, fmt.Errorf("%s: %s at line %d has no value", path, key.canonical, n)
		}
		if _, dup := fields[key.canonical]; dup {
			if !repeatable[key.canonical] {
				return nil, fmt.Errorf("%s: duplicate %s at line %d", path, key.canonical, n)
			}
			v = fields[key.canonical] + "," + v
		}
		fields[key.canonical] = v
	}
	if err := s.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("%s: a line exceeds %d bytes", path, bufio.MaxScanTokenSize)
		}
		return nil, err
	}
	for _, k := range []string{"Address", "PrivateKey", "PublicKey", "AllowedIPs", "Endpoint", "DNS"} {
		if fields[k] == "" {
			return nil, fmt.Errorf("%s: missing %s in [%s]", path, k, profileKeys[strings.ToLower(k)].section)
		}
	}
	return fields, nil
}

func items(value string) []string {
	var parts []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

// wg-quick accepts a bare Address; sing-box requires a prefix on every entry.
func interfaceAddresses(value string) (prefixes []string, hasIPv6 bool, err error) {
	for _, entry := range items(value) {
		p, perr := netip.ParsePrefix(entry)
		if perr != nil {
			addr, aerr := netip.ParseAddr(entry)
			if aerr != nil {
				return nil, false, fmt.Errorf("invalid Address %q", entry)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			hasIPv6 = true
		}
		prefixes = append(prefixes, p.String())
	}
	if len(prefixes) == 0 {
		return nil, false, errors.New("missing Address")
	}
	return prefixes, hasIPv6, nil
}

func peerRoutes(value string) (routes []string, v4Default, v6Default bool, err error) {
	var v4, v6 []netip.Prefix
	for _, entry := range items(value) {
		p, perr := netip.ParsePrefix(entry)
		if perr != nil {
			return nil, false, false, fmt.Errorf("invalid AllowedIPs %q", entry)
		}
		routes = append(routes, p.String())
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	if len(routes) == 0 {
		return nil, false, false, errors.New("missing AllowedIPs")
	}
	return routes, coversDefault(v4), coversDefault(v6), nil
}

// A default route is written either as /0 or as the two halves sing-tun itself
// installs (0.0.0.0/1 plus 128.0.0.0/1), which several providers ship.
func coversDefault(prefixes []netip.Prefix) bool {
	lower, upper := false, false
	for _, p := range prefixes {
		switch {
		case p.Bits() == 0:
			return true
		case p.Bits() != 1:
		// Masked, because the half a /1 covers is decided by its first bit and
		// not by the address it happens to be written with: 10.0.0.0/1 is the
		// lower half, the same as 0.0.0.0/1.
		case p.Masked().Addr().IsUnspecified():
			lower = true
		default:
			upper = true
		}
	}
	return lower && upper
}

func config(f map[string]string, listPath string) (object, error) {
	host, portText, err := net.SplitHostPort(f["Endpoint"])
	if err != nil {
		return nil, errors.New("invalid Endpoint (expected IP:port)")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, errors.New("endpoint must use an IP address to bootstrap tunnel DNS")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid endpoint port")
	}
	addresses, hasIPv6Address, err := interfaceAddresses(f["Address"])
	if err != nil {
		return nil, err
	}
	routes, v4Default, v6Default, err := peerRoutes(f["AllowedIPs"])
	if err != nil {
		return nil, err
	}
	if !v4Default {
		return nil, errors.New("default VPN routing requires an IPv4 full-tunnel peer (AllowedIPs must cover 0.0.0.0/0)")
	}
	tunnelsIPv6 := v6Default && hasIPv6Address

	peer := object{"address": host, "port": port, "public_key": f["PublicKey"], "allowed_ips": routes}
	if v := f["PresharedKey"]; v != "" {
		peer["pre_shared_key"] = v
	}
	if v := f["PersistentKeepalive"]; v != "" {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, errors.New("invalid PersistentKeepalive")
		}
		peer["persistent_keepalive_interval"] = n
	}
	endpoint := object{"type": "wireguard", "tag": tunnelTag, "address": addresses, "private_key": f["PrivateKey"], "peers": []object{peer}}
	if v := f["MTU"]; v != "" {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, errors.New("invalid MTU")
		}
		endpoint["mtu"] = n
	}

	var servers []object
	var tags []string
	for i, ip := range items(f["DNS"]) {
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil, errors.New("DNS entries must be IP addresses")
		}
		tag := fmt.Sprintf("vpn-dns-%d", i)
		tags = append(tags, tag)
		servers = append(servers, object{"type": "udp", "tag": tag, "server": ip, "detour": tunnelTag})
	}
	if len(tags) == 0 {
		return nil, errors.New("missing DNS")
	}
	// Bypassed hosts must also be resolved outside the tunnel, or a name that
	// only resolves on the local network cannot be reached by bypassing it.
	servers = append(servers, object{"type": "local", "tag": localResolver})
	dns := object{
		"servers":         servers,
		"rules":           []object{{"rule_set": []string{bypassTag}, "server": localResolver}},
		"final":           tags[0],
		"reverse_mapping": true,
	}
	// An IPv4-only peer drops every IPv6 packet the tun captures. Withholding
	// AAAA records keeps that traffic sealed inside the tunnel instead of
	// stalling clients on a route the peer cannot carry.
	if !tunnelsIPv6 {
		dns["strategy"] = "ipv4_only"
	}

	// runArguments registers 172.19.0.2, the peer in this /30, as the system resolver.
	tun := object{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "auto_route": true}
	route := object{
		"auto_detect_interface":   true,
		"default_domain_resolver": tags[0],
		"rule_set":                []object{{"type": "local", "tag": bypassTag, "format": "source", "path": listPath}},
		"rules": []object{
			{"action": "sniff"},
			{"protocol": "dns", "action": "hijack-dns"},
			{"rule_set": []string{bypassTag}, outboundField: directTag},
		},
		"final": tunnelTag,
	}
	return object{
		"dns":       dns,
		"inbounds":  []object{tun},
		"endpoints": []object{endpoint},
		"outbounds": []object{{"type": directTag, "tag": directTag}},
		"route":     route,
	}, nil
}

func writeJSON(path string, value any) error { return writeJSONChecked(path, value, nil) }

// The value is written to a temporary file and validated before it replaces the
// destination, so a rejected config cannot destroy a working profile.
func writeJSONChecked(path string, value any, check func(string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".wgsplit-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(value)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if check != nil {
		if err := check(f.Name()); err != nil {
			return err
		}
	}
	return os.Rename(f.Name(), path)
}

func readList(path string) (bypassList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bypassList{}, err
	}
	var l bypassList
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&l); err != nil {
		return bypassList{}, fmt.Errorf("%s: %w", path, err)
	}
	if l.Version < 1 || l.Version > listVersion {
		return bypassList{}, fmt.Errorf("%s: unsupported bypass list version %d (expected 1 to %d)", path, l.Version, listVersion)
	}
	// Several domain_suffix rules carry exactly the same meaning as one, and
	// DisallowUnknownFields guarantees no other rule field survived decoding.
	// Collapsing them keeps add and remove working on the same shape.
	var domains []string
	for _, r := range l.Rules {
		domains = append(domains, r.Domains...)
	}
	l.Version = listVersion
	l.Rules = []rule{}
	if len(domains) > 0 {
		l.Rules = []rule{{domains}}
	}
	return l, nil
}

// Every generated profile references the bypass list, and a missing list is the
// normal state before the first add, so recreate it instead of failing.
func openList(path string) (bypassList, error) {
	l, err := readList(path)
	if errors.Is(err, os.ErrNotExist) {
		return bypassList{Version: listVersion, Rules: []rule{}}, nil
	}
	return l, err
}

func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizeHost(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func hostname(name string) (string, error) {
	name = normalizeHost(name)
	if len(name) > 253 || net.ParseIP(name) != nil {
		return "", errors.New("expected a hostname")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", errors.New("expected a hostname with a domain part, e.g. myip.com (bypassing a whole top-level domain is not supported)")
	}
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return "", errors.New("expected a hostname, e.g. myip.com")
		}
	}
	return name, nil
}

func add(path, name string) error {
	name, err := hostname(name)
	if err != nil {
		return err
	}
	l, err := openList(path)
	if err != nil {
		return err
	}
	if len(l.Rules) == 0 {
		l.Rules = []rule{{}}
	}
	if slices.ContainsFunc(l.Rules[0].Domains, func(d string) bool { return sameHost(d, name) }) {
		return nil
	}
	l.Rules[0].Domains = append(l.Rules[0].Domains, name)
	return writeJSON(path, l)
}

// remove normalises but does not validate: an entry an older version accepted,
// or one added by hand, must still be removable through the CLI.
func remove(path, name string) error {
	name = normalizeHost(name)
	l, err := openList(path)
	if err != nil {
		return err
	}
	if len(l.Rules) == 0 {
		return fmt.Errorf("%s has no explicit bypass entry", name)
	}
	before := len(l.Rules[0].Domains)
	domains := slices.DeleteFunc(l.Rules[0].Domains, func(d string) bool { return sameHost(d, name) })
	if len(domains) == before {
		return fmt.Errorf("%s has no explicit bypass entry", name)
	}
	l.Rules = []rule{}
	if len(domains) > 0 {
		l.Rules = []rule{{domains}}
	}
	return writeJSON(path, l)
}

func main() {
	if err := rootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
