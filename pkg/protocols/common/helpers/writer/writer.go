package writer

import (
	"github.com/projectdiscovery/gologger"
	"line/pkg/output"
	"line/pkg/progress"
	//"line/pkg/reporting"
)

// WriteResult is a helper for writing results to the output
// , issuesClient reporting.Client
func WriteResult(data *output.InternalWrappedEvent, output output.Writer, progress progress.Progress) bool {
	// Handle the case where no result found for the template.
	// In this case, we just show misc information about the failed
	// match for the template.
	if !data.HasOperatorResult() {
		return false
	}
	var matched bool
	for _, result := range data.Results {
		if err := output.Write(result); err != nil {
			gologger.Warning().Msgf("Could not write output event: %s\n", err)
		}
		if !matched {
			matched = true
		}
		progress.IncrementMatched()
	}
	return matched
}
