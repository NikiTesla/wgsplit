package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const launchctl = "/bin/launchctl"

func jobLabel() string { return fmt.Sprintf("com.github.nikitesla.wgsplit.%d", os.Getuid()) }

func jobPlist(label, binary, config string) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>`)
	xml.EscapeText(&b, []byte(label))
	b.WriteString("</string><key>ProgramArguments</key><array>")
	for _, arg := range []string{binary, "run", "-c", config} {
		b.WriteString("<string>")
		xml.EscapeText(&b, []byte(arg))
		b.WriteString("</string>")
	}
	b.WriteString("</array><key>RunAtLoad</key><true/></dict></plist>")
	return b.Bytes()
}

// launchd requires root ownership for system job definitions. The temporary
// file exists only during bootstrap; the job is not installed at login or boot.
const bootstrapScript = `set -eu
dir=$(/usr/bin/mktemp -d /private/tmp/wgsplit.XXXXXXXX)
trap '/bin/rm -f "$dir/job.plist"; /bin/rmdir "$dir"' EXIT
umask 077
/bin/cat > "$dir/job.plist"
/bin/launchctl bootstrap system "$dir/job.plist"`

func privileged(stdin []byte, program string, args ...string) error {
	if os.Geteuid() != 0 {
		args = append([]string{program}, args...)
		program = "/usr/bin/sudo"
	}
	child := exec.Command(program, args...)
	child.Stdin = bytes.NewReader(stdin)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}

func (s store) start(cmd *cobra.Command, _ []string) error {
	path, err := s.existing(s.current)
	if err != nil {
		return err
	}
	binary, err := exec.LookPath("sing-box")
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	check := exec.Command(binary, "check", "-c", path)
	check.Stderr = cmd.ErrOrStderr()
	if err := check.Run(); err != nil {
		return err
	}
	target := "system/" + jobLabel()
	if exec.Command(launchctl, "print", target).Run() == nil {
		return errors.New("background job already loaded; use wgsplit status or wgsplit stop")
	}
	if err := privileged(jobPlist(jobLabel(), binary, path), "/bin/sh", "-c", bootstrapScript); err != nil {
		return fmt.Errorf("start %s: %w", s.current, err)
	}
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		state, err := exec.Command(launchctl, "print", target).Output()
		if err != nil {
			break
		}
		stateText := string(state)
		if strings.Contains(stateText, "\n\tstate = running\n") {
			fmt.Fprintf(cmd.OutOrStdout(), "Started %s in the background.\n", s.current)
			return nil
		}
		if strings.Contains(stateText, "\n\tlast exit code =") {
			if err := privileged(nil, launchctl, "bootout", target); err != nil {
				return fmt.Errorf("job exited; unloading it failed: %w", err)
			}
			return errors.New("sing-box exited during startup; use wgsplit run to see its logs")
		}
	}
	return fmt.Errorf("background job did not reach running state; inspect it with launchctl print %s and unload it with wgsplit stop", target)
}

func stop(cmd *cobra.Command, _ []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".sing-box")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return withLock(dir, func() error { return stopJob(cmd) })
}
func stopJob(cmd *cobra.Command) error {
	target := "system/" + jobLabel()
	if err := exec.Command(launchctl, "print", target).Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 113 {
			fmt.Fprintln(cmd.OutOrStdout(), "No wgsplit background job is loaded.")
			return nil
		}
		return fmt.Errorf("inspect background job: %w", err)
	}
	if err := privileged(nil, launchctl, "bootout", target); err != nil {
		return fmt.Errorf("stop background job: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Stopped the wgsplit background job.")
	return nil
}
