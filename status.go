package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// ps flattens argv. Only attribute a profile for the unambiguous single-config
// run form used by wgsplit. Other invocations can merge several config sources.
func runningConfig(command string) (config string, service bool) {
	args, ok := strings.CutPrefix(command, "sing-box ")
	if !ok {
		_, args, ok = strings.Cut(command, "/sing-box ")
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

func status(cmd *cobra.Command, _ []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	profiles := filepath.Join(home, ".sing-box", "profiles")
	snapshot, err := exec.Command("/bin/ps", "-axww", "-o", "pid=,stat=,comm=").Output()
	if err != nil {
		return fmt.Errorf("list processes: %w", err)
	}
	out := cmd.OutOrStdout()
	found := false
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
			return fmt.Errorf("inspect sing-box PID %s: %w", pid, err)
		}
		path, service := runningConfig(strings.TrimSpace(string(raw)))
		if !service {
			continue
		}
		found = true
		profile := "unavailable"
		if path != "" {
			profile = path
			if filepath.Dir(path) == profiles && filepath.Ext(path) == ".json" {
				profile = strings.TrimSuffix(filepath.Base(path), ".json") + " (" + path + ")"
			}
		}
		fmt.Fprintf(out, "sing-box running (PID %s) — profile: %s\n", pid, profile)
	}
	if !found {
		fmt.Fprintln(out, "sing-box is not running")
	}
	return nil
}
