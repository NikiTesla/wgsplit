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
	"slices"
	"strconv"
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
	return lockedCommand(use, short, args, func(s store, cmd *cobra.Command, args []string) error {
		if err := s.loadSelection(); err != nil {
			return err
		}
		return handle(s, cmd, args)
	})
}

func lockedCommand(use, short string, args cobra.PositionalArgs, handle handler) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: args, RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openStore()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(s.profiles, 0700); err != nil {
			return err
		}
		return withLock(cmd, s.dir, func() error {
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
	makeImport := func() *cobra.Command {
		cmd := command("import PROFILE.conf", "Import and validate a WireGuard profile", cobra.ExactArgs(1), store.importProfile)
		cmd.Flags().Bool("force", false, "replace an existing profile of the same name")
		return cmd
	}
	makeDefault := func() *cobra.Command {
		return command("default [NAME]", "Show or select the default profile for the next start", cobra.MaximumNArgs(1), store.selectDefault)
	}
	makeCheck := func() *cobra.Command {
		return command("check", "Validate the default profile configuration", cobra.NoArgs, store.checkProfile)
	}
	makeAdd := func() *cobra.Command {
		return lockedCommand("add HOSTNAME", "Bypass the VPN for a hostname and its subdomains", cobra.ExactArgs(1), editHosts(add))
	}
	makeRemove := func() *cobra.Command {
		return lockedCommand("remove HOSTNAME", "Remove an explicit bypass entry", cobra.ExactArgs(1), editHosts(remove))
	}
	profile := &cobra.Command{Use: "profile", Short: "Manage saved WireGuard profiles"}
	profile.AddCommand(makeImport(), makeDefault(), makeCheck(), command("list", "List profiles and mark the default", cobra.NoArgs, store.list))
	bypass := &cobra.Command{Use: "bypass", Short: "Manage hostnames that bypass the VPN for every profile"}
	bypass.AddCommand(makeAdd(), makeRemove(), lockedCommand("list", "List bypass hostnames", cobra.NoArgs, store.listBypass))
	start := command("start", "Start the default profile", cobra.NoArgs, func(s store, cmd *cobra.Command, args []string) error {
		foreground, err := cmd.Flags().GetBool("foreground")
		if err != nil {
			return err
		}
		if foreground {
			return s.runProfile(cmd, args)
		}
		return s.start(cmd, args)
	})
	start.Flags().Bool("foreground", false, "run in the foreground until Ctrl-C")
	root.AddCommand(profile, bypass, start,
		&cobra.Command{Use: "setup", Short: "Install sing-box with Go if needed", Args: cobra.NoArgs, RunE: setup},
		readCommand("status", "Show the background job and any running sing-box instances", store.status),
		&cobra.Command{Use: "stop", Short: "Stop your wgsplit background job", Args: cobra.NoArgs, RunE: stop})
	for _, old := range []*cobra.Command{makeImport(), makeDefault(), makeCheck(), makeAdd(), makeRemove(),
		command("list", "List saved profile names", cobra.NoArgs, store.list),
		command("show", "Show saved profiles and shared VPN bypass hostnames", cobra.NoArgs, store.show),
		command("run", "Run the default profile in the foreground", cobra.NoArgs, store.runProfile)} {
		old.Hidden = true
		root.AddCommand(old)
	}
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
			return "", fmt.Errorf("the default profile %q no longer exists; choose another with wgsplit profile default NAME or import it again", name)
		}
		return "", fmt.Errorf("no profile %q (wgsplit profile list shows saved profiles)", name)
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
		fmt.Fprintln(out, "(no profiles — run wgsplit profile import PROFILE.conf)")
		return nil
	}
	for _, name := range names {
		if cmd.Parent().Name() == "profile" && name == s.current {
			fmt.Fprintln(out, name, "(default)")
		} else {
			fmt.Fprintln(out, name)
		}
	}
	return nil
}

func (s store) listBypass(cmd *cobra.Command, _ []string) error {
	list, err := openList(s.domains)
	if err != nil {
		return err
	}
	for _, rule := range list.Rules {
		for _, host := range rule.Domains {
			fmt.Fprintln(cmd.OutOrStdout(), host)
		}
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
		if err := edit(s.domains, args[0]); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Bypass list saved. Running profiles using this list reload it automatically for new connections.")
		return nil
	}
}

func setup(cmd *cobra.Command, _ []string) error {
	binary, err := singboxPath()
	if errors.Is(err, exec.ErrNotFound) {
		install := exec.CommandContext(cmd.Context(), "go", "install", "-tags=with_wireguard,with_gvisor", "github.com/sagernet/sing-box/cmd/sing-box@v1.14.4")
		install.Stdin = cmd.InOrStdin()
		install.Stdout = cmd.OutOrStdout()
		install.Stderr = cmd.ErrOrStderr()
		if err := install.Run(); err != nil {
			return fmt.Errorf("install sing-box with Go: %w", err)
		}
		binary, err = singboxPath()
		if err != nil {
			return fmt.Errorf("add the Go binary directory to PATH: %w", err)
		}
	} else if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Using sing-box at", binary)
	return nil
}

func singboxPath() (string, error) {
	binary, err := exec.LookPath("sing-box")
	if err != nil {
		return "", fmt.Errorf("cannot locate sing-box on PATH (run wgsplit setup): %w", err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return "", err
	}

	output, err := exec.Command(binary, "version").Output()
	if err != nil {
		return "", fmt.Errorf("run %s version: %w", binary, err)
	}
	if err := validateSingboxBuild(string(output)); err != nil {
		return "", fmt.Errorf("%s: %w; replace it, or remove it from PATH and run wgsplit setup", binary, err)
	}
	return binary, nil
}

// LAN routes match on interface_address, which sing-box added in 1.13.0.
const minSingboxVersion = "1.13.0"

// Output that cannot be parsed passes: sing-box check still reports a build
// that cannot load the profile, just less clearly.
func validateSingboxBuild(versionOutput string) error {
	header, details, _ := strings.Cut(versionOutput, "\n")
	version, ok := strings.CutPrefix(strings.TrimSpace(header), "sing-box version ")
	if ok && versionBefore(version, minSingboxVersion) {
		return fmt.Errorf("sing-box %s is older than the required %s", version, minSingboxVersion)
	}
	for _, line := range strings.Split(details, "\n") {
		tags, ok := strings.CutPrefix(strings.TrimSpace(line), "Tags:")
		if ok && !slices.Contains(strings.Split(strings.TrimSpace(tags), ","), "with_wireguard") {
			return errors.New("sing-box was built without the with_wireguard tag")
		}
	}
	return nil
}

// Pre-release suffixes are ignored, so 1.13.0-beta.1 counts as 1.13.0.
func versionBefore(version, minimum string) bool {
	core, _, _ := strings.Cut(version, "-")
	have, want := strings.Split(core, "."), strings.Split(minimum, ".")
	if len(have) != len(want) {
		return false
	}
	for i := range want {
		h, err := strconv.Atoi(have[i])
		if err != nil {
			return false
		}
		w, _ := strconv.Atoi(want[i])
		if h != w {
			return h < w
		}
	}
	return false
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
	addr, err := tunIPv4Address(path, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Profile %q is valid (%s)\n", s.current, path)
	fmt.Fprintf(cmd.OutOrStdout(), "TUN IPv4: %s/30\nDNS peer: %s\n", addr, addr.Next())
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
	argv, err := prepareRunArguments(binary, path)
	if err != nil {
		return err
	}
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
	fmt.Fprintln(out, "Next: wgsplit bypass add HOSTNAME to send a host outside the VPN, then wgsplit start.")
	return nil
}
