package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/raxwqx/orbit/internal/dns"
	"github.com/raxwqx/orbit/internal/output"
)

const (
	version        = "0.2.0"
	maxTimeout     = 300
	defaultTimeout = 5
)

var (
	errHelp    = errors.New("help requested")
	errVersion = errors.New("version requested")
)

type options struct {
	target      string
	jsonOutput  bool
	timeoutSecs int
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	switch {
	case errors.Is(err, errHelp):
		usage(os.Stdout)
		return
	case errors.Is(err, errVersion):
		fmt.Fprintln(os.Stdout, "ORBIT "+version)
		return
	case err != nil:
		fmt.Fprintln(os.Stderr, "error:", err)
		usage(os.Stderr)
		os.Exit(2)
	}

	resolver := dns.New(time.Duration(opts.timeoutSecs) * time.Second)
	result := resolver.Lookup(opts.target)

	if opts.jsonOutput {
		if err := output.PrintJSON(os.Stdout, result); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	output.PrintTerminal(os.Stdout, result)
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: orbit [options] <domain>\n\n")
	fmt.Fprintf(w, "ORBIT v%s - DNS & network intelligence tool\n\n", version)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  -target <domain>   Target domain")
	fmt.Fprintln(w, "  --json             Output results as JSON")
	fmt.Fprintf(w, "  --timeout <sec>    DNS and DoH timeout in seconds (default: %d, max: %d)\n", defaultTimeout, maxTimeout)
	fmt.Fprintln(w, "  --version          Show version")
	fmt.Fprintln(w, "  -h, --help         Show help")
}

func parseArgs(args []string) (options, error) {
	opts := options{timeoutSecs: defaultTimeout}
	fs := flag.NewFlagSet("orbit", flag.ContinueOnError)
	// Errors are reported by main so the flag package must not print them and
	// its own usage copy a second time.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	flagTarget := fs.String("target", "", "Target domain")
	flagJSON := fs.Bool("json", false, "Output results as JSON")
	flagTimeout := fs.Int("timeout", defaultTimeout, "DNS and DoH timeout in seconds")

	// Help/version are handled here so flags can appear before or after the
	// positional target, e.g. both `orbit --json example.com` and
	// `orbit example.com --json` work as expected.
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "-h", "--help":
			return options{}, errHelp
		case "-version", "--version":
			return options{}, errVersion
		default:
			filtered = append(filtered, arg)
		}
	}

	positional := ""
	reordered := make([]string, 0, len(filtered))
	for i := 0; i < len(filtered); i++ {
		arg := filtered[i]
		if strings.HasPrefix(arg, "-") {
			reordered = append(reordered, arg)
			if arg == "-target" || arg == "--target" || arg == "-timeout" || arg == "--timeout" {
				if i+1 >= len(filtered) {
					return options{}, fmt.Errorf("%s requires a value", arg)
				}
				reordered = append(reordered, filtered[i+1])
				i++
			}
			continue
		}
		if positional != "" {
			return options{}, fmt.Errorf("unexpected argument: %s", arg)
		}
		positional = arg
	}

	if err := fs.Parse(reordered); err != nil {
		return options{}, err
	}

	if *flagTarget != "" && positional != "" {
		return options{}, fmt.Errorf("target specified more than once")
	}

	opts.target = strings.TrimSpace(*flagTarget)
	if opts.target == "" {
		opts.target = strings.TrimSpace(positional)
	}
	if opts.target == "" {
		return options{}, fmt.Errorf("target domain is required")
	}

	if *flagTimeout <= 0 {
		return options{}, fmt.Errorf("--timeout must be greater than 0")
	}
	if *flagTimeout > maxTimeout {
		return options{}, fmt.Errorf("--timeout must be at most %d seconds", maxTimeout)
	}

	opts.target = strings.ToLower(opts.target)
	if err := dns.ValidateTarget(opts.target); err != nil {
		return options{}, err
	}
	opts.target = strings.TrimSuffix(opts.target, ".")

	opts.jsonOutput = *flagJSON
	opts.timeoutSecs = *flagTimeout

	return opts, nil
}
