// Command datarake scans a directory tree for secrets.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/spf13/pflag"

	datarake "github.com/jcwoods/datarake/golang"
	"github.com/jcwoods/datarake/golang/config"
	"github.com/jcwoods/datarake/golang/match"
	"github.com/jcwoods/datarake/golang/rakeset"
	"github.com/jcwoods/datarake/golang/walker"
	"github.com/jcwoods/datarake/golang/writer"
)

// version is injected via -ldflags -X main.version=...
var version = "dev"

type options struct {
	paths []string

	format string
	output string

	secure         bool
	disableContext bool
	disableValue   bool
	summary        bool
	quiet          bool
	verbose        bool

	jobs         int
	configPath   string
	initConfig   bool
	matchTimeout time.Duration
}

// newFlagSet builds the flag set. Kept separate so usageString and
// parseCmdLine share one definition.
func newFlagSet(o *options) *pflag.FlagSet {
	fs := pflag.NewFlagSet("datarake", pflag.ContinueOnError)
	fs.SortFlags = false
	// pflag prints its own usage on --help and on a parse error. Both paths are
	// handled in main via usageString, so silence the built-in one to avoid
	// emitting the flag list twice.
	fs.Usage = func() {}
	fs.SetOutput(io.Discard)

	fs.StringVarP(&o.format, "format", "f", "json", "Output format (csv, json)")
	fs.StringVarP(&o.output, "output", "o", "", "Output location (defaults to stdout)")
	fs.BoolVarP(&o.secure, "secure", "s", false,
		"Enable secure output mode (no secrets displayed, secure context)")

	// argparse spells these -dx and -dv. pflag shorthands must be a single
	// character, so they are long flags here and argv is preprocessed.
	fs.BoolVar(&o.disableContext, "disable-context", false, "Disable output of context match")
	fs.BoolVar(&o.disableValue, "disable-value", false, "Disable output of secret matched")
	fs.BoolVar(&o.disableContext, "dx", false, "Alias for --disable-context")
	fs.BoolVar(&o.disableValue, "dv", false, "Alias for --disable-value")
	_ = fs.MarkHidden("dx")
	_ = fs.MarkHidden("dv")

	fs.BoolVarP(&o.summary, "summary", "u", false, "enable output of summary statistics")
	fs.BoolVarP(&o.quiet, "quiet", "q", false,
		"Do not output scan results, summary information only.")
	fs.BoolVarP(&o.verbose, "verbose", "v", false, "Enable verbose (diagnostic) output")
	fs.IntVarP(&o.jobs, "jobs", "j", 0,
		"Number of workers used to scan files (default: CPU count)")
	fs.StringVarP(&o.configPath, "config", "c", "",
		"Configuration file (defaults to the bundled datarake.yaml)")
	fs.BoolVar(&o.initConfig, "init-config", false,
		"Write the embedded default configuration to ./datarake.yaml and exit")
	fs.DurationVar(&o.matchTimeout, "match-timeout", time.Second,
		"Per-line regex match timeout; regexp2 backtracks, so this bounds it")

	return fs
}

func usageString() string {
	var o options
	fs := newFlagSet(&o)
	return "usage: datarake [options] [PATH ...]\n\n" + fs.FlagUsages()
}

// normalizeArgs rewrites argparse's multi-character short flags into the long
// forms pflag understands. Without this, pflag reads -dx as -d -x.
func normalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "-dx":
			out = append(out, "--dx")
		case "-dv":
			out = append(out, "--dv")
		default:
			out = append(out, a)
		}
	}
	return out
}

func parseCmdLine(argv []string) (*options, error) {
	o := &options{}
	fs := newFlagSet(o)

	if err := fs.Parse(normalizeArgs(argv[1:])); err != nil {
		return nil, err
	}

	switch o.format {
	case "csv", "json":
	default:
		return nil, fmt.Errorf("invalid choice for --format: %q (choose from csv, json)", o.format)
	}

	o.paths = fs.Args()
	if len(o.paths) == 0 {
		o.paths = []string{"."}
	}

	if o.jobs <= 0 {
		o.jobs = runtime.NumCPU()
		if o.jobs < 1 {
			o.jobs = 1
		}
	}

	return o, nil
}

// job is one file's scan, in flight or complete.
type job struct {
	ctx      *walker.Context
	findings []*match.RakeMatch
	stats    rakeset.Stats
	err      error
	done     chan struct{}
}

// initConfigFileName is the file written by --init-config.
const initConfigFileName = "datarake.yaml"

// writeInitConfig writes the embedded default configuration to
// initConfigFileName in the current directory, refusing to clobber a file
// that is already there.
func writeInitConfig() (int, error) {
	if _, err := os.Stat(initConfigFileName); err == nil {
		return 1, fmt.Errorf("%s already exists; not overwriting", initConfigFileName)
	} else if !os.IsNotExist(err) {
		return 1, fmt.Errorf("stat %s: %w", initConfigFileName, err)
	}
	if err := os.WriteFile(initConfigFileName, datarake.DefaultConfig, 0o644); err != nil {
		return 1, fmt.Errorf("write %s: %w", initConfigFileName, err)
	}
	fmt.Printf("wrote %s\n", initConfigFileName)
	return 0, nil
}

func run(o *options) (int, error) {
	if o.initConfig {
		return writeInitConfig()
	}

	oc := match.NewOutputConfig(o.secure, o.disableContext, o.disableValue)

	var cfg *config.Config
	var err error
	if o.configPath == "" {
		cfg, err = config.Load(datarake.DefaultConfig, o.matchTimeout)
	} else {
		cfg, err = config.LoadFile(o.configPath, o.matchTimeout)
	}
	if err != nil {
		return 1, err
	}

	out := io.Writer(os.Stdout)
	if o.output != "" {
		f, err := os.Create(o.output)
		if err != nil {
			return 1, fmt.Errorf("open output %s: %w", o.output, err)
		}
		defer f.Close()
		out = f
	}

	wopts := writer.Opts{W: out, Quiet: o.quiet, Summary: o.summary, Output: oc}
	var w writer.DataRakeWriter
	if o.format == "csv" {
		w = writer.NewCSVWriter(wopts)
	} else {
		w = writer.NewJSONWriter(wopts)
	}

	if err := w.InitOutput(); err != nil {
		return 1, err
	}
	if err := w.InitSecrets(); err != nil {
		return 1, err
	}

	// Totals are owned solely by this goroutine.
	var totals rakeset.Stats

	// The main goroutine's only jobs are handing files to workers and writing
	// what they return. Workers scan but never write. In-flight scans are
	// bounded so a huge tree does not materialize every result at once.
	sem := make(chan struct{}, o.jobs)
	maxInFlight := o.jobs * 4
	if maxInFlight < o.jobs {
		maxInFlight = o.jobs
	}
	pending := make([]*job, 0, maxInFlight)

	// drainOne blocks on the oldest outstanding scan, preserving walk order,
	// and emits its results from this goroutine. A failure on one file is
	// logged and skipped rather than aborting the run.
	drainOne := func() error {
		j := pending[0]
		pending = pending[1:]
		<-j.done

		if j.err != nil {
			fmt.Fprintf(os.Stderr, "* ERROR scanning %s: %v\n", j.ctx.FullPath, j.err)
			return nil
		}
		for _, f := range j.findings {
			if err := w.WriteSecret(f); err != nil {
				return err
			}
		}
		totals.Add(j.stats)
		return nil
	}

	for _, root := range o.paths {
		dw := walker.New(root, cfg.Walker.ExcludeSubdirs, o.verbose)
		err := dw.Walk(func(c *walker.Context) error {
			j := &job{ctx: c, done: make(chan struct{})}

			sem <- struct{}{}
			go func(j *job) {
				defer func() { <-sem }()
				j.findings, j.stats, j.err = cfg.RakeSet.Scan(j.ctx)
				close(j.done)
			}(j)

			pending = append(pending, j)
			if len(pending) >= maxInFlight {
				return drainOne()
			}
			return nil
		})
		if err != nil {
			// Drain what is in flight before reporting, so no goroutine is
			// left blocked and partial results are still emitted.
			for len(pending) > 0 {
				if derr := drainOne(); derr != nil {
					return 1, derr
				}
			}
			fmt.Fprintf(os.Stderr, "* ERROR walking %s: %v\n", root, err)
		}
	}

	for len(pending) > 0 {
		if err := drainOne(); err != nil {
			return 1, err
		}
	}

	if err := w.EndSecrets(); err != nil {
		return 1, err
	}
	if err := w.InitSummary(); err != nil {
		return 1, err
	}
	if err := w.WriteSummary(writer.Summary{
		Files: totals.Files, Lines: totals.Lines,
		Hits: totals.Hits, Bytes: totals.Bytes,
	}); err != nil {
		return 1, err
	}
	if err := w.EndSummary(); err != nil {
		return 1, err
	}
	if err := w.EndOutput(); err != nil {
		return 1, err
	}

	return 0, nil
}

func main() {
	o, err := parseCmdLine(os.Args)
	if err != nil {
		if err == pflag.ErrHelp {
			fmt.Print(usageString())
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "datarake: %v\n\n%s", err, usageString())
		os.Exit(2)
	}

	code, err := run(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "datarake: %v\n", err)
	}
	os.Exit(code)
}
