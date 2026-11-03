// The hosted lifecycle suite launches this distinct executable as a second
// standard user, so app identity cannot be confused with the root test runner.
// It sends one line through the routed path to the fixture's target and checks
// the complete reply of that platform's target: the Windows target echoes the
// request byte for byte, the Linux line server answers
// "pong <marker> <source address>".
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

const marker = "other-user"
const request = "ping " + marker + "\n"

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("NETSWITCH_LIFECYCLE_CI") != "1" || (len(os.Args) != 2 && len(os.Args) != 3) {
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	bound := len(os.Args) == 3
	if bound {
		ip := net.ParseIP(os.Args[2])
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid bind IPv4 %q", os.Args[2])
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	conn, err := dialer.Dial("tcp4", os.Args[1])
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if err := validReply(line); err != nil {
		return err
	}
	conn.SetDeadline(time.Time{})
	fmt.Println("ready")
	if bound {
		go func() {
			var b [1]byte
			if _, err := conn.Read(b[:]); err != nil {
				fmt.Println("aborted")
			}
		}()
	}
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
}

// validReply accepts only the complete reply of this platform's target, not
// any line that happens to carry the marker.
func validReply(line string) error {
	if runtime.GOOS == "windows" {
		if line != request {
			return fmt.Errorf("echo target answered %q, want %q", line, request)
		}
		return nil
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "pong" || fields[1] != marker || net.ParseIP(fields[2]) == nil {
		return fmt.Errorf("line server answered %q, want %q", line, "pong "+marker+" <address>")
	}
	return nil
}
