// The netswitch worker subcommand folds the helper's meter, outside, network,
// probe and policy modes into the control executable. Each runs independently
// with pipe-only output and bounded lifetime; workers cannot launch programs.
// query-supervised exercises the same restricted-process boundary as Control,
// including its deadline and stderr handling, for native parity diagnostics.
package observer

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
)

type options struct {
	mode   string
	parent uint32
	engine string
	once   bool
	// For run: the program and its arguments, passed on unchanged.
	program     string
	programArgs []string
}

const usage = `usage:
  netswitch worker meters  [--parent PID] [--once]
  netswitch worker outside [--parent PID] [--engine PATH] [--once]
  netswitch worker network [--parent PID] [--once]
  netswitch worker policy`

// Run executes one blocking read mode in a disposable worker process.
func Run(args []string) int {
	return run(args)
}

func run(args []string) int {
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n%s\n", err, usage)
		return 2
	}

	return runOptions(opts)
}

func parseArgs(args []string) (options, error) {
	if len(args) == 0 {
		return options{}, errors.New("choose a mode: meters, outside, network, probe, policy or run")
	}
	opts := options{mode: args[0]}
	// Everything after the program belongs to it, flags included.
	if opts.mode == "run" {
		return options{}, errors.New("workers cannot launch arbitrary programs")
	}
	if opts.mode != "meters" && opts.mode != "outside" && opts.mode != "network" && opts.mode != "policy" {
		return options{}, fmt.Errorf("unknown mode %q", opts.mode)
	}
	flags := flag.NewFlagSet(opts.mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	parent := flags.Uint64("parent", 0, "")
	flags.BoolVar(&opts.once, "once", false, "")
	if opts.mode == "outside" {
		flags.StringVar(&opts.engine, "engine", "", "")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return options{}, err
	}
	if flags.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *parent > math.MaxUint32 {
		return options{}, fmt.Errorf("--parent %d is not a process id", *parent)
	}
	opts.parent = uint32(*parent)
	return opts, nil
}

// WriteLine writes one reading as a single newline-terminated JSON line so the
// parent never sees half a line.
func WriteLine(reading any) error {
	line, err := json.Marshal(reading)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(line, '\n'))
	return err
}

func writeLine(reading any) error { return WriteLine(reading) }

// The server holds the other end of standard input and never writes to it.
// When the server ends, Windows closes that end and this read finishes.
func exitAtEndOfInput() {
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "stopped watching standard input: %v\n", err)
		return
	}
	os.Exit(0)
}
