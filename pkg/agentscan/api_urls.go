package agentscan

import "fmt"

const (
	analysisAPIVersion = "2026-07-10"
)

func analysisServerURL(apiURL string) string {
	return fmt.Sprintf("%s/hidden/mcp-scan/analysis-machine?version=%s", apiURL, analysisAPIVersion)
}
