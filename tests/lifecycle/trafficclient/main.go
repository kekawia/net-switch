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
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("NETSWITCH_LIFECYCLE_CI") != "1" || len(os.Args) != 2 {
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	conn, err := net.DialTimeout("tcp4", os.Args[1], 5*time.Second)
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
	fmt.Println("ready")
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
