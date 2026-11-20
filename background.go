//go:build darwin

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
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

// scutil owns the temporary Dynamic Store key. Its stdin stays open on fd 9
// across exec and closes when sing-box exits, including on SIGKILL.
// 172.19.0.2 is the peer of the tun address 172.19.0.1/30 set in main.go.
func runArguments(binary, config string) []string {
	const script = `set -eu
key="State:/Network/Service/wgsplit-$$/DNS"
tun_route_ready() {
    local iface
    iface=$(/sbin/route -n get -inet 172.19.0.2 2>/dev/null | /usr/bin/awk '$1 == "interface:" {print $2}')
    [[ $iface =~ ^utun[0-9]+$ ]] &&
        /sbin/ifconfig "$iface" | /usr/bin/grep -Eq '^[[:space:]]*inet 172[.]19[.]0[.]1[[:space:]]'
}
if tun_route_ready; then
    echo "the wgsplit tunnel address is already in use" >&2
    exit 1
fi
exec 9> >(/usr/sbin/scutil)
(
    trap '' PIPE
    for ((i=0; i<50; i++)); do
        kill -0 "$$" 2>/dev/null || exit 0
        if tun_route_ready; then
            if ! printf '%s\n' 'd.init' 'd.add ServerAddresses * 172.19.0.2' 'd.add SupplementalMatchDomains * ""' 'd.add SearchOrder # 1' "add $key temporary" >&9; then
                break
            fi
            exec 9>&-
            for attempt in 1 2 3; do
                /usr/sbin/scutil -w "$key" -t 1 && exit 0
            done
            break
        fi
        /bin/sleep 0.1
    done
    echo "could not register the tunnel DNS resolver" >&2
    kill -TERM "$$" 2>/dev/null
) &
exec "$1" run -c "$2"`
	return []string{"/bin/bash", "-c", script, "wgsplit", binary, config}
}

func jobPlist(label, binary, config, logFile string) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>`)
	writeEscaped(&b, label)
	b.WriteString("</string><key>ProgramArguments</key><array>")
	for _, arg := range runArguments(binary, config) {
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
# launchd truncates XML string arguments at numeric character references.
/usr/bin/plutil -convert binary1 "$dir/job.plist"
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
	pid      string
	exitCode string
}

// launchctl print is a human-readable debug dump with no stability contract, so
// read only the fields wgsplit needs and leave the rest unparsed.
func parseJobState(out []byte) launchdState {
	text := string(out)
	state := launchdState{loaded: true, running: strings.Contains(text, "\n\tstate = running\n")}
	if _, after, ok := strings.Cut(text, "\n\tpid = "); ok {
		pid, _, _ := strings.Cut(after, "\n")
		if n, err := strconv.Atoi(pid); err == nil && n > 0 {
			state.pid = pid
		}
	}
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
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
		time.Sleep(100 * time.Millisecond)
		state, err := jobState()
		if err != nil {
			return err
		}
		if !state.loaded {
			return fmt.Errorf("the background job disappeared during startup; see %s", logPath())
		}
		if state.running && state.pid != "" {
			processes, err := singboxProcesses()
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(processes, func(p process) bool { return p.pid == state.pid }) {
				continue
			}
			if err := exec.Command("/usr/sbin/scutil", "-w", "State:/Network/Service/wgsplit-"+state.pid+"/DNS", "-t", "1").Run(); err != nil {
				continue
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Started %s in the background. Logs: %s\n", s.current, logPath())
			fmt.Fprintln(out, "The job does not survive a reboot; run wgsplit start again afterwards.")
			return nil
		}
		if state.exitCode != "" {
			if err := privileged(nil, launchctl, "bootout", jobTarget()); err != nil {
				return fmt.Errorf("the background job exited (code %s) and clearing it failed: %w", state.exitCode, err)
			}
			return fmt.Errorf("the background job exited during startup (code %s); see %s", state.exitCode, logPath())
		}
	}
	return fmt.Errorf("the background job did not reach DNS readiness; see %s, inspect it with launchctl print %s and unload it with wgsplit stop", logPath(), jobTarget())
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
