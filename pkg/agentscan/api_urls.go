package agentscan

import "fmt"

const (
	analysisAPIVersion = "2026-07-10"
	controlAPIVersion  = "2025-08-28"
)

func analysisServerURL(apiURL string) string {
	return fmt.Sprintf("%s/hidden/mcp-scan/analysis-machine?version=%s", apiURL, analysisAPIVersion)
}

func controlServerURL(apiURL string) string {
	return fmt.Sprintf("%s/hidden/mcp-scan/push?version=%s", apiURL, controlAPIVersion)
}
