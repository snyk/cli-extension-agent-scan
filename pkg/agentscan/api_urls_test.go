package agentscan

import "testing"

func TestAnalysisServerURL(t *testing.T) {
	tests := []struct {
		name        string
		apiURL      string
		expectedURL string
	}{
		{
			name:        "default API",
			apiURL:      "https://api.snyk.io",
			expectedURL: "https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10",
		},
		{
			name:        "regional API",
			apiURL:      "https://api.eu.snyk.io",
			expectedURL: "https://api.eu.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := analysisServerURL(test.apiURL); actual != test.expectedURL {
				t.Fatalf("analysisServerURL(%q) = %q, want %q", test.apiURL, actual, test.expectedURL)
			}
		})
	}
}

func TestControlServerURLKeepsExistingAPIVersion(t *testing.T) {
	expected := "https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28"
	if actual := controlServerURL("https://api.snyk.io"); actual != expected {
		t.Fatalf("controlServerURL() = %q, want %q", actual, expected)
	}
}
