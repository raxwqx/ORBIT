package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/raxwqx/orbit/internal/dns"
	"github.com/raxwqx/orbit/internal/output"
)

const version = "0.1.1"

type options struct {
	target      string
	jsonOutput  bool
	timeoutSecs int
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		os.Exit(2)
	}

	if opts.target == "" {
		usage()
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

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: orbit [options] <domain>\n\n")
	fmt.Fprintf(os.Stderr, "ORBIT v%s - DNS & network intelligence tool\n\n", version)
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  -target <domain>   Target domain")
	fmt.Fprintln(os.Stderr, "  --json             Output results as JSON")
	fmt.Fprintln(os.Stderr, "  --timeout <sec>    DNS and DoH timeout in seconds (default: 5)")
	fmt.Fprintln(os.Stderr, "  --version          Show version")
	fmt.Fprintln(os.Stderr, "  -h, --help         Show help")
}

func parseArgs(args []string) (options, error) {
	opts := options{timeoutSecs: 5}
	fs := flag.NewFlagSet("orbit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage

	flagTarget := fs.String("target", "", "Target domain")
	flagJSON := fs.Bool("json", false, "Output results as JSON")
	flagTimeout := fs.Int("timeout", 5, "DNS and DoH timeout in seconds")

	// Help/version are handled here so flags can appear before or after the
	// positional target, e.g. both `orbit --json example.com` and
	// `orbit example.com --json` work as expected.
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-h", "--help":
			usage()
			os.Exit(0)
		case "--version":
			fmt.Fprintln(os.Stdout, "ORBIT "+version)
			os.Exit(0)
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

	opts.jsonOutput = *flagJSON
	opts.timeoutSecs = *flagTimeout
	opts.target = strings.TrimSuffix(opts.target, ".")
	if opts.target == "" {
		return options{}, fmt.Errorf("target domain is required")
	}

	return opts, nil
}
