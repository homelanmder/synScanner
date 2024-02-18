package utils

import (
	"strings"

	"line/pkg/catalog/config"
)

const (
	// TemplatesRepoURL is the URL for files in nuclei-templates repository
	TemplatesRepoURL = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
)

// TemplatePathURL returns the Path and URL for the provided template
func TemplatePathURL(fullPath string) (string, string) {
	var templateDirectory string
	configData := config.DefaultConfig
	if configData.TemplatesDirectory != "" && strings.HasPrefix(fullPath, configData.TemplatesDirectory) {
		templateDirectory = configData.TemplatesDirectory
	} else {
		return "", ""
	}

	finalPath := strings.TrimPrefix(strings.TrimPrefix(fullPath, templateDirectory), "/")
	templateURL := TemplatesRepoURL + finalPath
	return finalPath, templateURL
}
