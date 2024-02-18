package loader

import (
	"os"
	"sort"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"line/pkg/catalog"
	cfg "line/pkg/catalog/config"
	"line/pkg/catalog/loader/filter"
	"line/pkg/model/types/severity"
	"line/pkg/parsers"
	"line/pkg/protocols"
	"line/pkg/templates"
	templateTypes "line/pkg/templates/types"
	"line/pkg/types"
	"line/pkg/utils/stats"
)

// Config contains the configuration options for the loader
type Config struct {
	Templates                []string
	TemplateURLs             []string
	Workflows                []string
	WorkflowURLs             []string
	ExcludeTemplates         []string
	IncludeTemplates         []string
	RemoteTemplateDomainList []string

	Tags              []string
	ExcludeTags       []string
	Protocols         templateTypes.ProtocolTypes
	ExcludeProtocols  templateTypes.ProtocolTypes
	Authors           []string
	Severities        severity.Severities
	ExcludeSeverities severity.Severities
	IncludeTags       []string
	IncludeIds        []string
	ExcludeIds        []string
	IncludeConditions []string

	Catalog         catalog.Catalog
	ExecutorOptions protocols.ExecutorOptions
}

// Store is a storage for loaded nuclei templates
type Store struct {
	tagFilter      *filter.TagFilter
	pathFilter     *filter.PathFilter
	config         *Config
	finalTemplates []string
	finalWorkflows []string

	templates []*templates.Template
	workflows []*templates.Template

	preprocessor templates.Preprocessor

	// NotFoundCallback is called for each not found template
	// This overrides error handling for not found templatesss
	NotFoundCallback func(template string) bool
}

// NewConfig returns a new loader config
func NewConfig(options *types.Options, catalog catalog.Catalog, executerOpts protocols.ExecutorOptions) *Config {
	loaderConfig := Config{
		Templates:                options.Templates,
		Workflows:                options.Workflows,
		RemoteTemplateDomainList: options.RemoteTemplateDomainList,
		TemplateURLs:             options.TemplateURLs,
		WorkflowURLs:             options.WorkflowURLs,
		ExcludeTemplates:         options.ExcludedTemplates,
		Tags:                     options.Tags,
		ExcludeTags:              options.ExcludeTags,
		IncludeTemplates:         options.IncludeTemplates,
		Authors:                  options.Authors,
		Severities:               options.Severities,
		ExcludeSeverities:        options.ExcludeSeverities,
		IncludeTags:              options.IncludeTags,
		IncludeIds:               options.IncludeIds,
		ExcludeIds:               options.ExcludeIds,
		Protocols:                options.Protocols,
		ExcludeProtocols:         options.ExcludeProtocols,
		IncludeConditions:        options.IncludeConditions,
		Catalog:                  catalog,
		ExecutorOptions:          executerOpts,
	}
	return &loaderConfig
}

// New creates a new template store based on provided configuration
func New(config *Config) (*Store, error) {
	tagFilter, err := filter.New(&filter.Config{
		Tags:              config.Tags,
		ExcludeTags:       config.ExcludeTags,
		Authors:           config.Authors,
		Severities:        config.Severities,
		ExcludeSeverities: config.ExcludeSeverities,
		IncludeTags:       config.IncludeTags,
		IncludeIds:        config.IncludeIds,
		ExcludeIds:        config.ExcludeIds,
		Protocols:         config.Protocols,
		ExcludeProtocols:  config.ExcludeProtocols,
		IncludeConditions: config.IncludeConditions,
	})
	if err != nil {
		return nil, err
	}
	// Create a tag filter based on provided configuration
	store := &Store{
		config:    config,
		tagFilter: tagFilter,
		pathFilter: filter.NewPathFilter(&filter.PathFilterConfig{
			IncludedTemplates: config.IncludeTemplates,
			ExcludedTemplates: config.ExcludeTemplates,
		}, config.Catalog),
		finalTemplates: config.Templates,
		finalWorkflows: config.Workflows,
	}

	urlBasedTemplatesProvided := len(config.TemplateURLs) > 0 || len(config.WorkflowURLs) > 0
	if urlBasedTemplatesProvided {
		remoteTemplates, remoteWorkflows, err := getRemoteTemplatesAndWorkflows(config.TemplateURLs, config.WorkflowURLs, config.RemoteTemplateDomainList)
		if err != nil {
			return store, err
		}
		store.finalTemplates = append(store.finalTemplates, remoteTemplates...)
		store.finalWorkflows = append(store.finalWorkflows, remoteWorkflows...)
	}

	// Handle a dot as the current working directory
	if len(store.finalTemplates) == 1 && store.finalTemplates[0] == "." {
		currentDirectory, err := os.Getwd()
		if err != nil {
			return nil, errors.Wrap(err, "could not get current directory")
		}
		store.finalTemplates = []string{currentDirectory}
	}
	// Handle a case with no templates or workflows, where we use base directory
	if len(store.finalTemplates) == 0 && len(store.finalWorkflows) == 0 && !urlBasedTemplatesProvided {
		store.finalTemplates = []string{cfg.DefaultConfig.TemplatesDirectory}
	}
	return store, nil
}

// Templates returns all the templates in the store
func (store *Store) Templates() []*templates.Template {
	return store.templates
}

// Workflows returns all the workflows in the store
func (store *Store) Workflows() []*templates.Template {
	return store.workflows
}

// RegisterPreprocessor allows a custom preprocessor to be passed to the store to run against templates
func (store *Store) RegisterPreprocessor(preprocessor templates.Preprocessor) {
	store.preprocessor = preprocessor
}

// Load loads all the templates from a store, performs filtering and returns
// the complete compiled templates for a nuclei execution configuration.
func (store *Store) Load() {
	store.templates = store.LoadTemplates(store.finalTemplates)
}

var templateIDPathMap map[string]string

func init() {
	templateIDPathMap = make(map[string]string)
}

// ValidateTemplates takes a list of templates and validates them
// erroring out on discovering any faulty templates.
func (store *Store) ValidateTemplates() error {
	templatePaths, errs := store.config.Catalog.GetTemplatesPath(store.finalTemplates)
	store.logErroredTemplates(errs)
	store.logErroredTemplates(errs)
	filteredTemplatePaths := store.pathFilter.Match(templatePaths)

	if areTemplatesValid(store, filteredTemplatePaths) {
		return nil
	}
	return errors.New("errors occured during template validation")
}

func areTemplatesValid(store *Store, filteredTemplatePaths map[string]struct{}) bool {
	return areWorkflowOrTemplatesValid(store, filteredTemplatePaths, false, func(templatePath string, tagFilter *filter.TagFilter) (bool, error) {
		return parsers.LoadTemplate(templatePath, store.tagFilter, nil, store.config.Catalog)
	})
}

func areWorkflowOrTemplatesValid(store *Store, filteredTemplatePaths map[string]struct{}, isWorkflow bool, load func(templatePath string, tagFilter *filter.TagFilter) (bool, error)) bool {
	areTemplatesValid := true

	for templatePath := range filteredTemplatePaths {
		if _, err := load(templatePath, store.tagFilter); err != nil {
			if isParsingError("Error occurred loading template %s: %s\n", templatePath, err) {
				areTemplatesValid = false
				continue
			}
		}

		template, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
		if err != nil {
			if isParsingError("Error occurred parsing template %s: %s\n", templatePath, err) {
				areTemplatesValid = false
			}
		} else {
			if existingTemplatePath, found := templateIDPathMap[template.ID]; !found {
				templateIDPathMap[template.ID] = templatePath
			} else {
				areTemplatesValid = false
				gologger.Warning().Msgf("Found duplicate template ID during validation '%s' => '%s': %s\n", templatePath, existingTemplatePath, template.ID)
			}
		}

	}
	return areTemplatesValid
}

func isParsingError(message string, template string, err error) bool {
	if errors.Is(err, filter.ErrExcluded) {
		return false
	}
	if errors.Is(err, templates.ErrCreateTemplateExecutor) {
		return false
	}
	gologger.Error().Msgf(message, template, err)
	return true
}

// LoadTemplates takes a list of templates and returns paths for them
func (store *Store) LoadTemplates(templatesList []string) []*templates.Template {
	return store.LoadTemplatesWithTags(templatesList, nil)
}

// LoadTemplatesWithTags takes a list of templates and extra tags
// returning templates that match.
func (store *Store) LoadTemplatesWithTags(templatesList, tags []string) []*templates.Template {
	includedTemplates, errs := store.config.Catalog.GetTemplatesPath(templatesList)
	store.logErroredTemplates(errs)
	templatePathMap := store.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]*templates.Template, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, err := parsers.LoadTemplate(templatePath, store.tagFilter, tags, store.config.Catalog)
		if loaded || store.pathFilter.MatchIncluded(templatePath) {
			parsed, err := templates.Parse(templatePath, store.preprocessor, store.config.ExecutorOptions)
			if err != nil {
				// exclude templates not compatible with offline matching from total runtime warning stats
				if !errors.Is(err, templates.ErrIncompatibleWithOfflineMatching) {
					stats.Increment(parsers.RuntimeWarningsStats)
				}
				gologger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
			} else if parsed != nil {
				loadedTemplates = append(loadedTemplates, parsed)
			}
		}
		if err != nil {
			gologger.Warning().Msg(err.Error())
		}
	}

	sort.SliceStable(loadedTemplates, func(i, j int) bool {
		return loadedTemplates[i].Path < loadedTemplates[j].Path
	})

	return loadedTemplates
}

func (s *Store) logErroredTemplates(erred map[string]error) {
	for template, err := range erred {
		if s.NotFoundCallback == nil || !s.NotFoundCallback(template) {
			gologger.Error().Msgf("Could not find template '%s': %s", template, err)
		}
	}
}
