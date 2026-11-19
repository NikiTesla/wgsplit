//go:build darwin

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const launchctl = "/bin/launchctl"

func jobLabel() string  { return fmt.Sprintf("com.github.nikitesla.wgsplit.%d", os.Getuid()) }
func jobTarget() string { return "system/" + jobLabel() }
func logPath() string   { return fmt.Sprintf("/var/log/wgsplit.%d.log", os.Getuid()) }

// Writes to a bytes.Buffer cannot fail, so the escape error is not actionable.
func writeEscaped(b *bytes.Buffer, value string) { _ = xml.EscapeText(b, []byte(value)) }

func jobPlist(label, binary, config, logFile string) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>`)
	writeEscaped(&b, label)
	b.WriteString("</string><key>ProgramArguments</key><array>")
	for _, arg := range []string{binary, "run", "-c", config} {
		b.WriteString("<string>")
		writeEscaped(&b, arg)
		b.WriteString("</string>")
	}
	b.WriteString("</array>")
	// Without these keys launchd discards the job's output, leaving a crash
	// after startup with no trace anywhere.
	for _, key := range []string{"StandardOutPath", "StandardErrorPath"} {
		b.WriteString("<key>" + key + "</key><string>")
		writeEscaped(&b, logFile)
		b.WriteString("</string>")
	}
	b.WriteString("<key>RunAtLoad</key><true/></dict></plist>")
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
		args = append([]string{"--", program}, args...)
		program = "/usr/bin/sudo"
	}
	child := exec.Command(program, args...)
	child.Stdin = bytes.NewReader(stdin)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}

type launchdState struct {
	loaded   bool
	running  bool
	exitCode string
}

// launchctl print is a human-readable debug dump with no stability contract, so
// read only the two fields wgsplit needs and leave the rest unparsed.
func parseJobState(out []byte) launchdState {
	text := string(out)
	state := launchdState{loaded: true, running: strings.Contains(text, "\n\tstate = running\n")}
	if _, after, ok := strings.Cut(text, "\n\tlast exit code = "); ok {
		code, _, _ := strings.Cut(after, "\n")
		// A job that has never exited reports "(never exited)" here. Only a
		// numeric code is evidence of an exit, and start tears a job down on
		// that evidence.
		if code = strings.TrimSpace(code); isNumeric(code) {
			state.exitCode = code
		}
	}
	return state
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func jobState() (launchdState, error) {
	out, err := exec.Command(launchctl, "print", jobTarget()).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 113 {
			return launchdState{}, nil
		}
		return launchdState{}, fmt.Errorf("inspect background job: %w", err)
	}
	return parseJobState(out), nil
}

func exitText(code string) string {
	if code == "" {
		return "unknown"
	}
	return code
}

func (s store) start(cmd *cobra.Command, _ []string) error {
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
	state, err := jobState()
	if err != nil {
		return err
	}
	if state.loaded {
		if state.running {
			return errors.New("the background job is already running; use wgsplit status or wgsplit stop")
		}
		// A job without KeepAlive stays loaded after sing-box exits. Clearing it
		// here keeps start usable instead of refusing on behalf of a job that is
		// no longer carrying any traffic.
		fmt.Fprintf(cmd.ErrOrStderr(), "Clearing a stale background job (previous exit code %s).\n", exitText(state.exitCode))
		if err := privileged(nil, launchctl, "bootout", jobTarget()); err != nil {
			return fmt.Errorf("clear the stale background job: %w", err)
		}
	}
	running, err := singboxProcesses()
	if err != nil {
		return err
	}
	if len(running) > 0 {
		return fmt.Errorf("sing-box is already running (PID %s); stop it before starting the background job", running[0].pid)
	}
	if err := privileged(jobPlist(jobLabel(), binary, path, logPath()), "/bin/sh", "-c", bootstrapScript); err != nil {
		return fmt.Errorf("start %s: %w", s.current, err)
	}
	for range 20 {
		time.Sleep(100 * time.Millisecond)
		state, err := jobState()
		if err != nil {
			return err
		}
		if !state.loaded {
			return fmt.Errorf("the background job disappeared during startup; see %s", logPath())
		}
		if state.running {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Started %s in the background. Logs: %s\n", s.current, logPath())
			fmt.Fprintln(out, "The job does not survive a reboot; run wgsplit start again afterwards.")
			return nil
		}
		if state.exitCode != "" {
			if err := privileged(nil, launchctl, "bootout", jobTarget()); err != nil {
				return fmt.Errorf("sing-box exited (code %s) and clearing the job failed: %w", state.exitCode, err)
			}
			return fmt.Errorf("sing-box exited during startup (code %s); see %s", state.exitCode, logPath())
		}
	}
	return fmt.Errorf("the background job did not reach running state; inspect it with launchctl print %s and unload it with wgsplit stop", jobTarget())
}

// stop touches no file under ~/.sing-box, so it deliberately takes no lock: it
// must stay usable from a second terminal while start waits on a sudo prompt.
func stop(cmd *cobra.Command, _ []string) error {
	state, err := jobState()
	if err != nil {
		return err
	}
	if !state.loaded {
		fmt.Fprintln(cmd.OutOrStdout(), "No wgsplit background job is loaded.")
		return nil
	}
	if err := privileged(nil, launchctl, "bootout", jobTarget()); err != nil {
		return fmt.Errorf("stop background job: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Stopped the wgsplit background job.")
	return nil
}
