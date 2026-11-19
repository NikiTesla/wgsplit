package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

type store struct{ profiles, domains, selection, current string }
type handler func(store, *cobra.Command, []string) error

func command(use, short string, args cobra.PositionalArgs, handle handler) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: args, RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir := filepath.Join(home, ".sing-box")
		s := store{profiles: filepath.Join(dir, "profiles"), domains: filepath.Join(dir, "direct-domains.json"), selection: filepath.Join(dir, "default.json")}
		if err := os.MkdirAll(s.profiles, 0700); err != nil {
			return err
		}
		return withLock(dir, func() error {
			data, err := os.ReadFile(s.selection)
			if err == nil {
				if err = json.Unmarshal(data, &s.current); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return handle(s, cmd, args)
		})
	}}
}

func withLock(dir string, action func() error) error {
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	return action()
}

func rootCommand() *cobra.Command {
	root := &cobra.Command{Use: "wgsplit", Version: "0.0.1", Short: "Manage sing-box WireGuard profiles and VPN bypass hostnames", SilenceUsage: true, SilenceErrors: true}
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(
		&cobra.Command{Use: "status", Short: "Show running sing-box instances and their active profiles", Args: cobra.NoArgs, RunE: status},
		command("import PROFILE.conf", "Import and validate a WireGuard profile", cobra.ExactArgs(1), store.importProfile),
		command("default [NAME]", "Show or select the default profile", cobra.MaximumNArgs(1), store.selectDefault),
		command("list", "List saved profile names", cobra.NoArgs, store.list),
		command("show", "Show saved profiles and shared VPN bypass hostnames", cobra.NoArgs, store.show),
		command("add HOSTNAME", "Bypass the VPN for a hostname and its subdomains", cobra.ExactArgs(1), editHosts(add)),
		command("remove HOSTNAME", "Remove an explicit hostname from the shared VPN bypass list", cobra.ExactArgs(1), editHosts(remove)),
		command("check", "Validate the default sing-box profile", cobra.NoArgs, store.launch),
		command("start", "Start the default profile in the background", cobra.NoArgs, store.start),
		&cobra.Command{Use: "stop", Short: "Stop your wgsplit background job", Args: cobra.NoArgs, RunE: stop},
		command("run", "Start the default sing-box profile", cobra.NoArgs, store.launch))
	return root
}

var validName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)

func (s store) profilePath(name string) (string, error) {
	if name == "" {
		return "", errors.New("import a profile first")
	}
	if !validName.MatchString(name) {
		return "", errors.New("invalid profile name")
	}
	return filepath.Join(s.profiles, name+".json"), nil
}
func (s store) existing(name string) (string, error) {
	path, err := s.profilePath(name)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("expected a regular profile file")
	}
	return path, nil
}
func (s store) names() ([]string, error) {
	entries, err := os.ReadDir(s.profiles)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, strings.TrimSuffix(entry.Name(), ".json"))
		}
	}
	return names, nil
}
func (s store) list(cmd *cobra.Command, _ []string) error {
	names, err := s.names()
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Fprintln(cmd.OutOrStdout(), n)
	}
	return nil
}
func (s store) show(cmd *cobra.Command, _ []string) error {
	names, err := s.names()
	if err != nil {
		return err
	}
	rules, err := readList(s.domains)
	if err != nil && !(errors.Is(err, os.ErrNotExist) && len(names) == 0) {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Profiles")
	if len(names) == 0 {
		fmt.Fprintln(out, "  (none)")
	}
	for _, name := range names {
		mark := ""
		if name == s.current {
			mark = " (default)"
		}
		fmt.Fprintf(out, "  %s%s  %s\n", name, mark, filepath.Join(s.profiles, name+".json"))
	}
	fmt.Fprintln(out, "VPN bypass hostnames (including subdomains)")
	var hosts []string
	for _, rule := range rules.Rules {
		hosts = append(hosts, rule.Domains...)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(out, "  (none)")
	}
	for _, host := range hosts {
		fmt.Fprintf(out, "  %s\n", host)
	}
	return nil
}
func (s store) selectDefault(cmd *cobra.Command, args []string) error {
	name := s.current
	if len(args) == 1 {
		name = args[0]
	}
	if _, err := s.existing(name); err != nil {
		return err
	}
	if len(args) == 1 {
		if err := writeJSON(s.selection, name, nil); err != nil {
			return err
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), name)
	return nil
}
func editHosts(edit func(string, string) error) handler {
	return func(s store, cmd *cobra.Command, args []string) error {
		if _, err := s.existing(s.current); err != nil {
			return err
		}
		if err := edit(s.domains, args[0]); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Bypass list saved. Running profiles using this list reload it automatically for new connections.")
		return nil
	}
}
func (s store) launch(cmd *cobra.Command, _ []string) error {
	path, err := s.existing(s.current)
	if err != nil {
		return err
	}
	binary, err := exec.LookPath("sing-box")
	if err != nil {
		return err
	}
	argv := []string{binary, cmd.Name(), "-c", path}
	if cmd.Name() == "run" && os.Geteuid() != 0 {
		argv = append([]string{"/usr/bin/sudo"}, argv...)
	}
	return syscall.Exec(argv[0], argv, os.Environ())
}
func (s store) importProfile(cmd *cobra.Command, args []string) error {
	base := filepath.Base(args[0])
	name := strings.TrimSuffix(base, filepath.Ext(base))
	path, err := s.profilePath(name)
	if err != nil {
		return err
	}
	binary, err := exec.LookPath("sing-box")
	if err != nil {
		return err
	}
	fields, err := parse(args[0])
	if err != nil {
		return err
	}
	cfg, err := config(fields, s.domains)
	if err != nil {
		return err
	}
	if _, err = os.Stat(s.domains); errors.Is(err, os.ErrNotExist) {
		if err = writeJSON(s.domains, list{3, []rule{}}, nil); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	err = writeJSON(path, cfg, func(tmp string) error {
		check := exec.Command(binary, "check", "-c", tmp)
		check.Stderr = cmd.ErrOrStderr()
		return check.Run()
	})
	if err != nil {
		return err
	}
	if s.current == "" {
		if err := writeJSON(s.selection, name, nil); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "sudo %s run -c %s\n", quote(binary), quote(path))
	return err
}
