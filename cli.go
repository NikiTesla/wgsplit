//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

type store struct{ dir, profiles, domains, selection, current string }
type handler func(store, *cobra.Command, []string) error

// openStore resolves the single on-disk layout every command shares.
func openStore() (store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return store{}, err
	}
	dir := filepath.Join(home, ".sing-box")
	return store{
		dir:       dir,
		profiles:  filepath.Join(dir, "profiles"),
		domains:   filepath.Join(dir, "direct-domains.json"),
		selection: filepath.Join(dir, "default.json"),
	}, nil
}

func (s *store) loadSelection() error {
	data, err := os.ReadFile(s.selection)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.current); err != nil {
		return fmt.Errorf("%s is unreadable: %w (delete the file to reset the default profile)", s.selection, err)
	}
	return nil
}

func command(use, short string, args cobra.PositionalArgs, handle handler) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: args, RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openStore()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(s.profiles, 0700); err != nil {
			return err
		}
		return withLock(cmd, s.dir, func() error {
			if err := s.loadSelection(); err != nil {
				return err
			}
			return handle(s, cmd, args)
		})
	}}
}

// Commands that only report state must not queue behind a command holding the
// lock, which start does across an interactive sudo prompt.
func readCommand(use, short string, handle handler) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openStore()
		if err != nil {
			return err
		}
		if err := s.loadSelection(); err != nil {
			return err
		}
		return handle(s, cmd, args)
	}}
}

func withLock(cmd *cobra.Command, dir string, action func() error) error {
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Waiting for another wgsplit command to finish...")
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
			return err
		}
	}
	return action()
}

func rootCommand() *cobra.Command {
	root := &cobra.Command{Use: "wgsplit", Version: "0.0.1", Short: "Manage sing-box WireGuard profiles and VPN bypass hostnames", SilenceUsage: true, SilenceErrors: true}
	root.CompletionOptions.DisableDefaultCmd = true
	importCmd := command("import PROFILE.conf", "Import and validate a WireGuard profile", cobra.ExactArgs(1), store.importProfile)
	importCmd.Flags().Bool("force", false, "replace an existing profile of the same name")
	root.AddCommand(
		readCommand("status", "Show the background job and any running sing-box instances", store.status),
		importCmd,
		command("default [NAME]", "Show or select the default profile", cobra.MaximumNArgs(1), store.selectDefault),
		command("list", "List saved profile names", cobra.NoArgs, store.list),
		command("show", "Show saved profiles and shared VPN bypass hostnames", cobra.NoArgs, store.show),
		command("add HOSTNAME", "Bypass the VPN for a hostname and its subdomains", cobra.ExactArgs(1), editHosts(add)),
		command("remove HOSTNAME", "Remove an explicit hostname from the shared VPN bypass list", cobra.ExactArgs(1), editHosts(remove)),
		command("check", "Validate the default sing-box profile", cobra.NoArgs, store.checkProfile),
		command("start", "Start the default profile as a background job", cobra.NoArgs, store.start),
		&cobra.Command{Use: "stop", Short: "Stop your wgsplit background job", Args: cobra.NoArgs, RunE: stop},
		command("run", "Run the default profile in the foreground with sudo (Ctrl-C stops it)", cobra.NoArgs, store.runProfile))
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
	// Lstat, not Stat: IsRegular must reject a symlink rather than follow it.
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if name == s.current {
			return "", fmt.Errorf("the default profile %q no longer exists; choose another with wgsplit default NAME or import it again", name)
		}
		return "", fmt.Errorf("no profile %q (wgsplit list shows saved profiles)", name)
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink; profiles must be regular files", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
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
	out := cmd.OutOrStdout()
	if len(names) == 0 {
		fmt.Fprintln(out, "(no profiles — run wgsplit import PROFILE.conf)")
		return nil
	}
	for _, name := range names {
		fmt.Fprintln(out, name)
	}
	return nil
}

func (s store) show(cmd *cobra.Command, _ []string) error {
	names, err := s.names()
	if err != nil {
		return err
	}
	rules, err := openList(s.domains)
	if err != nil {
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
	out := cmd.OutOrStdout()
	if len(args) == 0 {
		fmt.Fprintln(out, name)
		return nil
	}
	previous := s.current
	if err := writeJSON(s.selection, name); err != nil {
		return err
	}
	fmt.Fprintln(out, name)
	if state, err := jobState(); err == nil && state.running && previous != name {
		fmt.Fprintln(out, "A background job is still running the previously selected profile; run wgsplit stop && wgsplit start to switch.")
	}
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

func singboxPath() (string, error) {
	binary, err := exec.LookPath("sing-box")
	if err != nil {
		return "", fmt.Errorf("sing-box not found in PATH: %w", err)
	}
	return filepath.Abs(binary)
}

func singboxCheck(binary, config string, stderr io.Writer) error {
	check := exec.Command(binary, "check", "-c", config)
	check.Stderr = stderr
	return check.Run()
}

func (s store) checkProfile(cmd *cobra.Command, _ []string) error {
	path, err := s.existing(s.current)
	if err != nil {
		return err
	}
	binary, err := singboxPath()
	if err != nil {
		return err
	}
	if err := singboxCheck(binary, path, cmd.ErrOrStderr()); err != nil {
		return fmt.Errorf("%s is not a valid sing-box profile: %w", path, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Profile %q is valid (%s)\n", s.current, path)
	return nil
}

func (s store) runProfile(cmd *cobra.Command, _ []string) error {
	path, err := s.existing(s.current)
	if err != nil {
		return err
	}
	binary, err := singboxPath()
	if err != nil {
		return err
	}
	if err := refuseSecondInstance(); err != nil {
		return err
	}
	argv := []string{binary, "run", "-c", path}
	if os.Geteuid() != 0 {
		argv = append([]string{"/usr/bin/sudo", "--"}, argv...)
	}
	return syscall.Exec(argv[0], argv, os.Environ())
}

// Every generated profile claims the same tun addresses with auto_route, so two
// instances fight over the default route and the first to exit tears down
// routes the other still needs.
func refuseSecondInstance() error {
	if state, err := jobState(); err == nil && state.loaded {
		return errors.New("the wgsplit background job is loaded; run wgsplit stop first")
	}
	running, err := singboxProcesses()
	if err != nil {
		return err
	}
	if len(running) > 0 {
		return fmt.Errorf("sing-box is already running (PID %s); stop it before starting another instance", running[0].pid)
	}
	return nil
}

func (s store) importProfile(cmd *cobra.Command, args []string) error {
	base := filepath.Base(args[0])
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if name == "" || !validName.MatchString(name) {
		return fmt.Errorf("profile name %q, taken from the file name, may only contain letters, digits, dot, dash and underscore — rename the file", name)
	}
	path := filepath.Join(s.profiles, name+".json")
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return err
	}
	switch _, statErr := os.Lstat(path); {
	case statErr == nil && !force:
		return fmt.Errorf("profile %q already exists (%s); pass --force to replace it", name, path)
	case statErr != nil && !errors.Is(statErr, fs.ErrNotExist):
		return statErr
	}
	binary, err := singboxPath()
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
	if _, err := os.Stat(s.domains); errors.Is(err, fs.ErrNotExist) {
		if err := writeJSON(s.domains, bypassList{listVersion, []rule{}}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	err = writeJSONChecked(path, cfg, func(tmp string) error {
		return singboxCheck(binary, tmp, cmd.ErrOrStderr())
	})
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Imported %q to %s\n", name, path)
	if servers := items(fields["DNS"]); len(servers) > 1 {
		fmt.Fprintf(out, "Only the first DNS server (%s) is used; sing-box does not fail over between servers.\n", servers[0])
	}
	if s.current == "" {
		if err := writeJSON(s.selection, name); err != nil {
			return err
		}
		fmt.Fprintln(out, "It is now the default profile.")
	}
	fmt.Fprintln(out, "Next: wgsplit add HOSTNAME to send a host outside the VPN, then wgsplit start.")
	return nil
}
