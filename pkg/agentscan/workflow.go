package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.5.16"

	AgentScanBinaryChecksumLinuxAmd64   = "0101a9d007a0486704c43feaf75e3266c4240057eca1c5a42ea33389f2c5d5f5"
	AgentScanBinaryChecksumLinuxArm64   = "cf5c4ee25afbef7084650f37a90727eaaca4f2b0df9fd1724667dbc11eca3c75"
	AgentScanBinaryChecksumMacOSArm64   = "29cb22c57ecb04d789e86812fcc30b2567343f3af97fa19439463882b9df2589"
	AgentScanBinaryChecksumMacOSIntel   = "1defc0e49299357f084710dca1f56d5a8f2a98879c7cb773dc93746653a1a317"
	AgentScanBinaryChecksumWindowsAmd64 = "61b5a50010b933142f4765e692afb27d878f6ecda6562576bbcc2d22d94dafe7"
)

var (
	ScanWorkflowID workflow.Identifier = workflow.NewWorkflowIdentifier(ScanWorkflowIDStr)

	ScanDataTypeID workflow.Identifier = workflow.NewTypeIdentifier(ScanWorkflowID, ScanWorkflowIDStr)
)

// Init initializes the DepGraph workflow.
func Init(engine workflow.Engine) error {
	flags := getFlagSet()
	engine.GetConfiguration().AddAlternativeKeys(FlagTenantID, []string{"SNYK_TENANT_ID"})
	_, err := engine.Register(
		ScanWorkflowID,
		workflow.ConfigurationOptionsFromFlagset(flags),
		Workflow)
	if err != nil {
		return fmt.Errorf("failed to register workflow: %w", err)
	}

	return nil
}
