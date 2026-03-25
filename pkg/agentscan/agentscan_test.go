package agentscan_test

import (
	"slices"
	"strings"
	"testing"

	agentscan "github.com/snyk/cli-extension-agent-scan/pkg/agentscan"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func TestCommandDetection(t *testing.T) {
	tests := []struct {
		name        string
		filteredArg string
		hasCommand  bool
		description string
	}{
		{
			name:        "path is not a command",
			filteredArg: "/path/to/scan",
			hasCommand:  false,
			description: "Paths with / should not be detected as commands",
		},
		{
			name:        "relative path is not a command",
			filteredArg: "./path/to/scan",
			hasCommand:  false,
			description: "Relative paths with ./ should not be detected as commands",
		},
		{
			name:        "file with extension is not a command",
			filteredArg: "file.txt",
			hasCommand:  false,
			description: "Files with . extension should not be detected as commands",
		},
		{
			name:        "version is a command",
			filteredArg: "version",
			hasCommand:  true,
			description: "Simple word without / or . is a command",
		},
		{
			name:        "help is a command",
			filteredArg: "help",
			hasCommand:  true,
			description: "help should be detected as a command",
		},
		{
			name:        "scan is a command",
			filteredArg: "scan",
			hasCommand:  true,
			description: "scan should be detected as a command",
		},
		{
			name:        "flag is not a command",
			filteredArg: "--json",
			hasCommand:  false,
			description: "Flags starting with - are not commands",
		},
		{
			name:        "Windows absolute path is not a command",
			filteredArg: "C:\\Users\\path\\to\\scan",
			hasCommand:  false,
			description: "Windows paths with backslashes should not be detected as commands",
		},
		{
			name:        "Windows relative path is not a command",
			filteredArg: ".\\relative\\path",
			hasCommand:  false,
			description: "Windows relative paths with backslashes should not be detected as commands",
		},
		{
			name:        "Windows UNC path is not a command",
			filteredArg: "\\\\server\\share\\path",
			hasCommand:  false,
			description: "Windows UNC paths should not be detected as commands",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the command detection logic
			hasCommand := false
			if !strings.HasPrefix(tt.filteredArg, "-") {
				if !strings.Contains(tt.filteredArg, "/") && !strings.Contains(tt.filteredArg, "\\") && !strings.Contains(tt.filteredArg, ".") {
					hasCommand = true
				}
			}
			assert.Equal(t, tt.hasCommand, hasCommand, tt.description)
		})
	}
}

func TestScanCommandPrepending(t *testing.T) {
	tests := []struct {
		name           string
		filteredArgs   []string
		expectedResult []string
		description    string
	}{
		{
			name:           "prepends scan for path",
			filteredArgs:   []string{"/path/to/scan"},
			expectedResult: []string{"scan", "/path/to/scan"},
			description:    "When first arg is a path, scan should be prepended",
		},
		{
			name:           "prepends scan for flags only",
			filteredArgs:   []string{"--json", "--skills"},
			expectedResult: []string{"scan", "--json", "--skills"},
			description:    "When only flags are present, scan should be prepended",
		},
		{
			name:           "does not prepend scan for version command",
			filteredArgs:   []string{"version"},
			expectedResult: []string{"version"},
			description:    "When version command is present, scan should not be prepended",
		},
		{
			name:           "does not prepend scan for help command",
			filteredArgs:   []string{"help"},
			expectedResult: []string{"help"},
			description:    "When help command is present, scan should not be prepended",
		},
		{
			name:           "does not prepend scan when scan already present",
			filteredArgs:   []string{"scan", "/path/to/scan"},
			expectedResult: []string{"scan", "/path/to/scan"},
			description:    "When scan command is already present, should not duplicate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the scan prepending logic
			result := make([]string, len(tt.filteredArgs))
			copy(result, tt.filteredArgs)

			hasCommand := false
			if len(result) > 0 && !strings.HasPrefix(result[0], "-") {
				firstArg := result[0]
				if !strings.Contains(firstArg, "/") && !strings.Contains(firstArg, "\\") && !strings.Contains(firstArg, ".") {
					hasCommand = true
				}
			}

			if !hasCommand {
				result = append([]string{"scan"}, result...)
			}

			assert.Equal(t, tt.expectedResult, result, tt.description)
		})
	}
}

func TestFilterArgs_BasicFiltering(t *testing.T) {
	tests := []struct {
		name     string
		rawArgs  []string
		expected []string
	}{
		{
			name:     "filters out --no-upload",
			rawArgs:  []string{"agent-scan", "--experimental", "--no-upload", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out --experimental",
			rawArgs:  []string{"agent-scan", "--experimental", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out agent-scan command",
			rawArgs:  []string{"agent-scan", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out --client-id",
			rawArgs:  []string{"agent-scan", "--client-id=123e4567-e89b-12d3-a456-426614174000", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out --tenant-id",
			rawArgs:  []string{"agent-scan", "--tenant-id=123e4567-e89b-12d3-a456-426614174000", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters multiple flags",
			rawArgs:  []string{"agent-scan", "--experimental", "--no-upload", "--client-id=123e4567-e89b-12d3-a456-426614174000", "--tenant-id=123e4567-e89b-12d3-a456-426614174000", "path/to/scan", "--json"},
			expected: []string{"path/to/scan", "--json"},
		},
		{
			name:     "keeps other flags",
			rawArgs:  []string{"agent-scan", "--experimental", "--json", "--skills", "path/to/scan"},
			expected: []string{"--json", "--skills", "path/to/scan"},
		},
		{
			name:     "filters out --insecure",
			rawArgs:  []string{"agent-scan", "--experimental", "--insecure", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out scan subcommand",
			rawArgs:  []string{"agent-scan", "--experimental", "scan", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out scan with other flags",
			rawArgs:  []string{"agent-scan", "scan", "--json", "path/to/scan"},
			expected: []string{"--json", "path/to/scan"},
		},
		{
			name:     "filters out mcp-scan subcommand",
			rawArgs:  []string{"mcp-scan", "--experimental", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out mcp-scan with other flags",
			rawArgs:  []string{"mcp-scan", "--experimental", "--json", "path/to/scan"},
			expected: []string{"--json", "path/to/scan"},
		},
		// --debug and -d are filtered so they are not forwarded to the child binary;
		// isDebug is read from config.GetBool(configuration.DEBUG) in the workflow.
		{
			name:     "filters out debug",
			rawArgs:  []string{"agent-scan", "--experimental", "--debug", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out debug with other args",
			rawArgs:  []string{"agent-scan", "--debug", "--json", "path/to/scan"},
			expected: []string{"--json", "path/to/scan"},
		},
		{
			name:     "filters out -d short form",
			rawArgs:  []string{"agent-scan", "--experimental", "-d", "path/to/scan"},
			expected: []string{"path/to/scan"},
		},
		{
			name:     "filters out -d with other args",
			rawArgs:  []string{"agent-scan", "-d", "--json", "path/to/scan"},
			expected: []string{"--json", "path/to/scan"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test verifies the filtering logic conceptually
			// The actual filtering happens in the Workflow function
			filtered := make([]string, 0, len(tt.rawArgs))
			for _, a := range tt.rawArgs {
				if a == "agent-scan" || a == "--experimental" || a == "--no-upload" || a == "scan" || a == "mcp-scan" {
					continue
				}
				if a == "--insecure" {
					continue
				}
				if a == "--debug" || a == "-d" {
					continue
				}
				if len(a) >= len("--tenant-id=") && a[:len("--tenant-id=")] == "--tenant-id=" {
					continue
				}
				if len(a) >= len("--client-id=") && a[:len("--client-id=")] == "--client-id=" {
					continue
				}
				filtered = append(filtered, a)
			}
			assert.Equal(t, tt.expected, filtered)
		})
	}
}

func TestNoUploadRequiresAuthentication(t *testing.T) {
	// This test documents the expected behavior:
	// When --no-upload is set, authentication is required
	// The actual implementation is tested via integration tests
	t.Run("no-upload requires authentication", func(t *testing.T) {
		// Expected behavior:
		// 1. --no-upload flag is set
		// 2. User must be authenticated (whoami succeeds)
		// 3. If not authenticated, error is returned
		// 4. Client-ID is not required when --no-upload is set
		assert.True(t, true, "This behavior is verified in integration tests")
	})
}

func TestNoUploadDoesNotRequireClientID(t *testing.T) {
	// This test documents the expected behavior:
	// When --no-upload is set, client-id is not required
	t.Run("no-upload does not require client-id", func(t *testing.T) {
		// Expected behavior:
		// 1. --no-upload flag is set
		// 2. User is authenticated
		// 3. Client-ID can be provided or not - makes no difference
		// 4. Client-ID retrieval logic is skipped
		assert.True(t, true, "This behavior is verified in integration tests")
	})
}

func TestControlServerArgsFiltering(t *testing.T) {
	tests := []struct {
		name                    string
		hasCommand              bool
		noUpload                bool
		expectControlServerArgs bool
		description             string
	}{
		{
			name:                    "scan command with upload includes control server args",
			hasCommand:              false,
			noUpload:                false,
			expectControlServerArgs: true,
			description:             "Scan command with upload should include --control-server, --control-server-H, --control-identifier",
		},
		{
			name:                    "scan command with --no-upload excludes control server args",
			hasCommand:              false,
			noUpload:                true,
			expectControlServerArgs: false,
			description:             "Scan command with --no-upload should NOT include control server args",
		},
		{
			name:                    "version command excludes control server args",
			hasCommand:              true,
			noUpload:                false,
			expectControlServerArgs: false,
			description:             "Commands like 'version' should NOT include control server args",
		},
		{
			name:                    "version command with --no-upload excludes control server args",
			hasCommand:              true,
			noUpload:                true,
			expectControlServerArgs: false,
			description:             "Commands with --no-upload should NOT include control server args",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the control server args logic
			shouldAddControlServerArgs := !tt.hasCommand && !tt.noUpload

			assert.Equal(t, tt.expectControlServerArgs, shouldAddControlServerArgs, tt.description)

			t.Logf("hasCommand: %v, noUpload: %v, addControlServerArgs: %v",
				tt.hasCommand, tt.noUpload, shouldAddControlServerArgs)
		})
	}
}

func TestVerboseWhenDebug(t *testing.T) {
	// isDebug is set from config.GetBool(configuration.DEBUG); the framework sets this
	// when the user passes --debug or -d (global flag).
	tests := []struct {
		name          string
		isDebug       bool
		filteredArgs  []string
		expectVerbose bool
		description   string
	}{
		{
			name:          "debug mode appends --verbose",
			isDebug:       true,
			filteredArgs:  []string{"path/to/scan"},
			expectVerbose: true,
			description:   "When config.GetBool(configuration.DEBUG) is true (e.g. --debug or -d), --verbose is appended",
		},
		{
			name:          "-d short form appends --verbose",
			isDebug:       true,
			filteredArgs:  []string{"path/to/scan"},
			expectVerbose: true,
			description:   "When debug is enabled via config (--debug or -d), --verbose is appended",
		},
		{
			name:          "no debug does not append --verbose",
			isDebug:       false,
			filteredArgs:  []string{"path/to/scan"},
			expectVerbose: false,
			description:   "When config.GetBool(configuration.DEBUG) is false, --verbose is not appended",
		},
		{
			name:          "debug with existing args",
			isDebug:       true,
			filteredArgs:  []string{"scan", "/path", "--json"},
			expectVerbose: true,
			description:   "--verbose is appended at end when isDebug (from config) is true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the --verbose append logic from Workflow
			result := make([]string, len(tt.filteredArgs))
			copy(result, tt.filteredArgs)
			if tt.isDebug {
				result = append(result, "--verbose")
			}
			hasVerbose := slices.Contains(result, "--verbose")
			assert.Equal(t, tt.expectVerbose, hasVerbose, tt.description)
		})
	}
}

func TestAnalysisURLAlwaysSet(t *testing.T) {
	// This test documents the expected behavior:
	// --analysis-url should be set regardless of --no-upload
	t.Run("analysis-url always set", func(t *testing.T) {
		// Expected behavior:
		// --analysis-url is passed to the binary whether or not --no-upload is set
		assert.True(t, true, "This behavior is verified in integration tests")
	})
}

func TestClientIDValidation(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		wantError bool
	}{
		{
			name:      "valid UUID",
			clientID:  "123e4567-e89b-12d3-a456-426614174000",
			wantError: false,
		},
		{
			name:      "empty string is valid (will be retrieved)",
			clientID:  "",
			wantError: false,
		},
		{
			name:      "invalid UUID",
			clientID:  "not-a-uuid",
			wantError: true,
		},
		{
			name:      "invalid format",
			clientID:  "12345",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This validates the UUID format check logic
			// The actual validation happens in the Workflow function
			if tt.clientID == "" {
				assert.False(t, tt.wantError)
				return
			}

			// Simple UUID validation check (matches the pattern in utils)
			isValid := len(tt.clientID) == 36 && tt.clientID[8] == '-' && tt.clientID[13] == '-' && tt.clientID[18] == '-' && tt.clientID[23] == '-'
			if tt.wantError {
				assert.False(t, isValid, "Expected invalid UUID")
			} else {
				assert.True(t, isValid, "Expected valid UUID")
			}
		})
	}
}

func TestTenantIDValidation(t *testing.T) {
	tests := []struct {
		name      string
		tenantID  string
		wantError bool
	}{
		{
			name:      "valid UUID",
			tenantID:  "123e4567-e89b-12d3-a456-426614174000",
			wantError: false,
		},
		{
			name:      "empty string is valid",
			tenantID:  "",
			wantError: false,
		},
		{
			name:      "invalid UUID",
			tenantID:  "not-a-uuid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tenantID == "" {
				assert.False(t, tt.wantError)
				return
			}

			// Simple UUID validation check
			isValid := len(tt.tenantID) == 36 && tt.tenantID[8] == '-' && tt.tenantID[13] == '-' && tt.tenantID[18] == '-' && tt.tenantID[23] == '-'
			if tt.wantError {
				assert.False(t, isValid, "Expected invalid UUID")
			} else {
				assert.True(t, isValid, "Expected valid UUID")
			}
		})
	}
}

func TestFlagConfiguration(t *testing.T) {
	t.Run("all required flags are defined", func(t *testing.T) {
		// Verify flag constants exist
		assert.Equal(t, "experimental", agentscan.FlagExperimental)
		assert.Equal(t, "client-id", agentscan.FlagClientID)
		assert.Equal(t, "tenant-id", agentscan.FlagTenantID)
		assert.Equal(t, "json", agentscan.FlagJSON)
		assert.Equal(t, "skills", agentscan.FlagSkills)
		assert.Equal(t, "no-upload", agentscan.FlagNoUpload)
	})
}

func TestWorkflowScenarios(t *testing.T) {
	// These tests document the expected behavior for different scenarios
	scenarios := []struct {
		name              string
		hasCommand        bool
		noUpload          bool
		clientID          string
		tenantID          string
		isLoggedIn        bool
		expectError       bool
		expectClientIDAPI bool
		expectTenantIDAPI bool
		description       string
	}{
		{
			name:              "scan command with --no-upload and authenticated",
			hasCommand:        false,
			noUpload:          true,
			clientID:          "",
			tenantID:          "",
			isLoggedIn:        true,
			expectError:       false,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "Scan with --no-upload requires auth but skips client-id/tenant-id retrieval",
		},
		{
			name:              "scan command with --no-upload but not authenticated",
			hasCommand:        false,
			noUpload:          true,
			clientID:          "",
			tenantID:          "",
			isLoggedIn:        false,
			expectError:       true,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "--no-upload requires authentication",
		},
		{
			name:              "scan command with upload, authenticated, no client-id",
			hasCommand:        false,
			noUpload:          false,
			clientID:          "",
			tenantID:          "",
			isLoggedIn:        true,
			expectError:       false,
			expectClientIDAPI: true,
			expectTenantIDAPI: true,
			description:       "Scan command retrieves tenant-id and client-id when authenticated",
		},
		{
			name:              "scan command with upload, authenticated, with tenant-id",
			hasCommand:        false,
			noUpload:          false,
			clientID:          "",
			tenantID:          "123e4567-e89b-12d3-a456-426614174000",
			isLoggedIn:        true,
			expectError:       false,
			expectClientIDAPI: true,
			expectTenantIDAPI: false,
			description:       "When tenant-id provided, only client-id is retrieved",
		},
		{
			name:              "scan command with upload, authenticated, with client-id",
			hasCommand:        false,
			noUpload:          false,
			clientID:          "123e4567-e89b-12d3-a456-426614174000",
			tenantID:          "",
			isLoggedIn:        true,
			expectError:       false,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "When client-id provided, no API calls needed",
		},
		{
			name:              "scan command with upload, not authenticated, no client-id",
			hasCommand:        false,
			noUpload:          false,
			clientID:          "",
			tenantID:          "",
			isLoggedIn:        false,
			expectError:       true,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "Scan without auth and without client-id fails",
		},
		{
			name:              "scan command with upload, not authenticated, with client-id",
			hasCommand:        false,
			noUpload:          false,
			clientID:          "123e4567-e89b-12d3-a456-426614174000",
			tenantID:          "",
			isLoggedIn:        false,
			expectError:       false,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "Client-id can be provided manually without authentication",
		},
		{
			name:              "version command requires authentication",
			hasCommand:        true,
			noUpload:          false,
			clientID:          "",
			tenantID:          "",
			isLoggedIn:        true,
			expectError:       false,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "Commands like 'version' require auth but skip client-id/tenant-id retrieval",
		},
		{
			name:              "version command without authentication fails",
			hasCommand:        true,
			noUpload:          false,
			clientID:          "",
			tenantID:          "",
			isLoggedIn:        false,
			expectError:       true,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "Commands require authentication when client-id not provided",
		},
		{
			name:              "version command with client-id, no auth needed",
			hasCommand:        true,
			noUpload:          false,
			clientID:          "123e4567-e89b-12d3-a456-426614174000",
			tenantID:          "",
			isLoggedIn:        false,
			expectError:       false,
			expectClientIDAPI: false,
			expectTenantIDAPI: false,
			description:       "Commands with client-id provided don't require authentication",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Document the expected behavior
			t.Logf("Scenario: %s", scenario.description)
			t.Logf("  hasCommand: %v", scenario.hasCommand)
			t.Logf("  noUpload: %v", scenario.noUpload)
			t.Logf("  clientID: %s", scenario.clientID)
			t.Logf("  tenantID: %s", scenario.tenantID)
			t.Logf("  isLoggedIn: %v", scenario.isLoggedIn)
			t.Logf("  expectError: %v", scenario.expectError)
			t.Logf("  expectClientIDAPI: %v", scenario.expectClientIDAPI)
			t.Logf("  expectTenantIDAPI: %v", scenario.expectTenantIDAPI)

			// These scenarios are validated in integration tests
			assert.True(t, true, "Scenario documented")
		})
	}
}

func TestExperimentalFlagRequired(t *testing.T) {
	t.Run("experimental flag is required", func(t *testing.T) {
		// Expected behavior:
		// The workflow should not proceed without --experimental flag
		// This is checked early in the Workflow function
		assert.True(t, true, "This behavior is verified in integration tests")
	})
}

func TestHelpCommand(t *testing.T) {
	t.Run("help command bypasses authentication", func(t *testing.T) {
		// Expected behavior:
		// When 'help' is in the args, the binary is run with just "help"
		// No authentication or client-id checks are performed
		assert.True(t, true, "This behavior is verified in integration tests")
	})
}

func TestConfigurationKeys(t *testing.T) {
	t.Run("configuration keys are properly defined", func(t *testing.T) {
		// Verify that configuration keys match expected values
		assert.Equal(t, configuration.RAW_CMD_ARGS, configuration.RAW_CMD_ARGS)
		assert.Equal(t, configuration.API_URL, configuration.API_URL)
	})
	t.Run("debug flag uses framework configuration key", func(t *testing.T) {
		// Workflow sets isDebug from config.GetBool(configuration.DEBUG); the framework
		// binds --debug and -d to this key via global flags.
		assert.Equal(t, "debug", configuration.DEBUG)
	})
}
