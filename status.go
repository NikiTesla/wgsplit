//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type process struct{ pid, config string }

// ps flattens argv. Only attribute a profile for the unambiguous single-config
// run form used by wgsplit. Other invocations can merge several config sources.
func runningConfig(argv string) (configPath string, isRun bool) {
	args, ok := strings.CutPrefix(argv, "sing-box ")
	if !ok {
		_, args, ok = strings.Cut(argv, "/sing-box ")
	}
	// macOS may hide argv when the process belongs to another user.
	if !ok {
		return "", true
	}
	if args == "run" {
		return "", true
	}
	if rest, ok := strings.CutPrefix(args, "run "); ok {
		for _, flag := range []string{"-c ", "--config ", "--config="} {
			if path, ok := strings.CutPrefix(rest, flag); ok && filepath.IsAbs(path) && !strings.Contains(path, " -") {
				return filepath.Clean(path), true
			}
		}
		return "", true
	}
	if strings.HasPrefix(args, "-") {
		return "", true
	}
	return "", false
}

func singboxProcesses() ([]process, error) {
	snapshot, err := exec.Command("/bin/ps", "-axww", "-o", "pid=,stat=,comm=").Output()
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	var found []process
	for _, line := range strings.Split(string(snapshot), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || strings.Contains(fields[1], "Z") || filepath.Base(fields[len(fields)-1]) != "sing-box" {
			continue
		}
		pid := fields[0]
		raw, err := exec.Command("/bin/ps", "-ww", "-p", pid, "-o", "args=").Output()
		var exited *exec.ExitError
		if errors.As(err, &exited) && exited.ExitCode() == 1 && len(raw) == 0 {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect sing-box PID %s: %w", pid, err)
		}
		path, isRun := runningConfig(strings.TrimSpace(string(raw)))
		if !isRun {
			continue
		}
		found = append(found, process{pid: pid, config: path})
	}
	return found, nil
}

func (s store) describe(path string) string {
	if path == "" {
		return "unavailable"
	}
	if filepath.Dir(path) == s.profiles && filepath.Ext(path) == ".json" {
		return strings.TrimSuffix(filepath.Base(path), ".json") + " (" + path + ")"
	}
	return path
}

func (s store) status(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	if s.current != "" {
		fmt.Fprintf(out, "Default profile: %s\n", s.current)
	}
	// start and stop manage a launchd job, so status has to report that job and
	// not just whatever sing-box processes happen to exist.
	// A launchctl hiccup must not hide the process list below it, which is the
	// rest of what the user asked for.
	switch state, err := jobState(); {
	case err != nil:
		fmt.Fprintf(out, "Background job: unknown (%v)\n", err)
	case state.running:
		fmt.Fprintln(out, "Background job: running")
	case state.loaded:
		fmt.Fprintf(out, "Background job: loaded but not running (last exit code %s) — wgsplit start clears it\n", exitText(state.exitCode))
	default:
		fmt.Fprintln(out, "Background job: not loaded")
	}
	running, err := singboxProcesses()
	if err != nil {
		return err
	}
	if len(running) == 0 {
		fmt.Fprintln(out, "sing-box is not running")
		return nil
	}
	for _, p := range running {
		fmt.Fprintf(out, "sing-box running (PID %s) — profile: %s\n", p.pid, s.describe(p.config))
	}
	return nil
}
