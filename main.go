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
type list struct {
	Version int    `json:"version"`
	Rules   []rule `json:"rules"`
}

func parse(path string) (map[string]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	fields := map[string]string{}
	seen := map[string]bool{}
	section := ""
	allowed := map[string]string{"PrivateKey": "Interface", "Address": "Interface", "DNS": "Interface", "MTU": "Interface", "PublicKey": "Peer", "PresharedKey": "Peer", "Endpoint": "Peer", "AllowedIPs": "Peer", "PersistentKeepalive": "Peer"}
	s := bufio.NewScanner(f)
	for n := 1; s.Scan(); n++ {
		line, _, _ := strings.Cut(s.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "[Interface]" || line == "[Peer]" {
			section = strings.Trim(line, "[]")
			if seen[section] {
				return nil, fmt.Errorf("repeated %s section at line %d (one peer supported)", section, n)
			}
			seen[section] = true
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || section == "" || allowed[k] != section || v == "" {
			return nil, fmt.Errorf("unsupported or malformed profile entry at line %d", n)
		}
		if _, ok := fields[k]; ok {
			if k != "Address" && k != "DNS" && k != "AllowedIPs" {
				return nil, fmt.Errorf("duplicate %s", k)
			}
			v = fields[k] + "," + v
		}
		fields[k] = v
	}
	if e := s.Err(); e != nil {
		return nil, e
	}
	for _, k := range []string{"Address", "PrivateKey", "PublicKey", "AllowedIPs", "Endpoint", "DNS"} {
		if fields[k] == "" {
			return nil, fmt.Errorf("missing %s", k)
		}
	}
	return fields, nil
}

func items(value string) []string {
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func config(f map[string]string, listPath string) (object, error) {
	host, portText, e := net.SplitHostPort(f["Endpoint"])
	if e != nil {
		return nil, errors.New("invalid Endpoint (expected IP:port)")
	}
	if _, e := netip.ParseAddr(host); e != nil {
		return nil, errors.New("Endpoint must use an IP address to bootstrap tunnel DNS")
	}
	port, e := strconv.ParseUint(portText, 10, 16)
	if e != nil || port == 0 {
		return nil, errors.New("invalid endpoint port")
	}
	routes := items(f["AllowedIPs"])
	full := false
	for _, r := range routes {
		p, e := netip.ParsePrefix(r)
		if e != nil {
			return nil, errors.New("invalid AllowedIPs")
		}
		if p.Bits() == 0 && p.Addr().Is4() {
			full = true
		}
	}
	if !full {
		return nil, errors.New("default VPN routing requires an IPv4 full-tunnel peer")
	}
	peer := object{"address": host, "port": port, "public_key": f["PublicKey"], "allowed_ips": routes}
	endpoint := object{"type": "wireguard", "tag": "wg", "address": items(f["Address"]), "private_key": f["PrivateKey"], "peers": []object{peer}}
	if v := f["PresharedKey"]; v != "" {
		peer["pre_shared_key"] = v
	}
	for _, opt := range []struct {
		key, field string
		target     object
	}{{"MTU", "mtu", endpoint}, {"PersistentKeepalive", "persistent_keepalive_interval", peer}} {
		if v := f[opt.key]; v != "" {
			n, e := strconv.ParseUint(v, 10, 16)
			if e != nil {
				return nil, fmt.Errorf("invalid %s", opt.key)
			}
			opt.target[opt.field] = n
		}
	}
	var servers []object
	for i, ip := range items(f["DNS"]) {
		if _, e := netip.ParseAddr(ip); e != nil {
			return nil, errors.New("DNS entries must be IP addresses")
		}
		servers = append(servers, object{"type": "udp", "tag": fmt.Sprintf("vpn-dns-%d", i), "server": ip, "detour": "wg"})
	}
	return object{"dns": object{"servers": servers, "final": "vpn-dns-0", "reverse_mapping": true}, "inbounds": []object{{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "auto_route": true}}, "endpoints": []object{endpoint}, "outbounds": []object{{"type": "direct", "tag": "direct"}}, "route": object{"auto_detect_interface": true, "default_domain_resolver": "vpn-dns-0", "rule_set": []object{{"type": "local", "tag": "bypass", "format": "source", "path": listPath}}, "rules": []object{{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}, {"rule_set": []string{"bypass"}, "outbound": "direct"}}, "final": "wg"}}, nil
}

func writeJSON(path string, value any, validate func(string) error) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".wgsplit-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	e = enc.Encode(value)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if validate != nil {
		if e := validate(f.Name()); e != nil {
			return e
		}
	}
	return os.Rename(f.Name(), path)
}

func readList(path string) (list, error) {
	data, e := os.ReadFile(path)
	if e != nil {
		return list{}, e
	}
	var l list
	if !json.Valid(data) {
		return list{}, errors.New("invalid bypass list JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&l); e != nil {
		return list{}, e
	}
	if l.Version != 3 {
		return list{}, errors.New("unexpected bypass list format")
	}
	return l, nil
}

func hostname(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	label := regexp.MustCompile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
	if len(name) > 253 || net.ParseIP(name) != nil {
		return "", errors.New("expected a hostname")
	}
	for _, part := range strings.Split(name, ".") {
		if !label.MatchString(part) {
			return "", errors.New("expected a hostname, e.g. myip.com")
		}
	}
	return name, nil
}

func add(path, name string) error {
	name, e := hostname(name)
	if e != nil {
		return e
	}
	l, e := readList(path)
	if e != nil {
		return e
	}
	if len(l.Rules) > 1 {
		return errors.New("unexpected bypass list format")
	}
	if len(l.Rules) == 0 {
		l.Rules = []rule{{}}
	}
	for _, d := range l.Rules[0].Domains {
		if d == name {
			return nil
		}
	}
	l.Rules[0].Domains = append(l.Rules[0].Domains, name)
	return writeJSON(path, l, nil)
}

func remove(path, name string) error {
	name, err := hostname(name)
	if err != nil {
		return err
	}
	l, err := readList(path)
	if err != nil {
		return err
	}
	found := false
	kept := l.Rules[:0]
	for _, r := range l.Rules {
		before := len(r.Domains)
		r.Domains = slices.DeleteFunc(r.Domains, func(value string) bool { return strings.EqualFold(strings.TrimSuffix(value, "."), name) })
		if len(r.Domains) != before {
			found = true
			if len(r.Domains) == 0 {
				continue
			}
		}
		kept = append(kept, r)
	}
	if !found {
		return fmt.Errorf("%s has no explicit bypass entry", name)
	}
	l.Rules = kept
	return writeJSON(path, l, nil)
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func main() {
	if e := rootCommand().Execute(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
