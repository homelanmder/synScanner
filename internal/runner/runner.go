package runner

import (
	"context"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"
	"github.com/homelanmder/synScanner/pkg/catalog"
	"github.com/homelanmder/synScanner/pkg/output"
	"github.com/homelanmder/synScanner/pkg/parsers"
	"github.com/homelanmder/synScanner/pkg/progress"
	"github.com/homelanmder/synScanner/pkg/protocols/common/hosterrorscache"
	"github.com/homelanmder/synScanner/pkg/protocols/common/interactsh"
	"github.com/homelanmder/synScanner/pkg/types"
	"github.com/homelanmder/synScanner/pkg/utils/yaml"
	"time"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	Output     output.Writer
	Interactsh *interactsh.Client
	Options    *types.Options
	Catalog    catalog.Catalog
	Progress   progress.Progress
	Colorizer  aurora.Aurora

	RateLimiter *ratelimit.Limiter
	hostErrors  hosterrorscache.CacheInterface
	ResumeCfg   *types.ResumeCfg
}

// New creates a new client for running the enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		Options: options,
	}

	// TODO: refactor to pass options reference globally without cycles
	parsers.NoStrictSyntax = options.NoStrictSyntax
	yaml.StrictSyntax = !options.NoStrictSyntax

	//runner.Catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)

	// Create the output file if asked
	outputWriter, err := output.NewStandardWriter(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output file")
	}
	runner.Output = outputWriter

	var progressErr error
	statsInterval := options.StatsInterval
	runner.Progress, progressErr = progress.NewStatsTicker(statsInterval, options.EnableProgressBar, options.StatsJSON, options.Metrics, options.Cloud, options.MetricsPort)
	if progressErr != nil {
		return nil, progressErr
	}

	opts := interactsh.DefaultOptions(runner.Output, runner.Progress)
	opts.Debug = runner.Options.Debug
	opts.NoColor = runner.Options.NoColor
	if options.InteractshURL != "" {
		opts.ServerURL = options.InteractshURL
	}
	opts.Authorization = options.InteractshToken
	opts.CacheSize = options.InteractionsCacheSize
	opts.Eviction = time.Duration(options.InteractionsEviction) * time.Second
	opts.CooldownPeriod = time.Duration(options.InteractionsCoolDownPeriod) * time.Second
	opts.PollDuration = time.Duration(options.InteractionsPollDuration) * time.Second
	opts.NoInteractsh = runner.Options.NoInteractsh
	opts.StopAtFirstMatch = runner.Options.StopAtFirstMatch
	opts.Debug = runner.Options.Debug
	opts.DebugRequest = runner.Options.DebugRequests
	opts.DebugResponse = runner.Options.DebugResponse

	if options.RateLimitMinute > 0 {
		runner.RateLimiter = ratelimit.New(context.Background(), uint(options.RateLimitMinute), time.Minute)
	} else if options.RateLimit > 0 {
		runner.RateLimiter = ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	} else {
		runner.RateLimiter = ratelimit.NewUnlimited(context.Background())
	}
	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	if r.Output != nil {
		r.Output.Close()
	}

	if r.RateLimiter != nil {
		r.RateLimiter.Stop()
	}
}
