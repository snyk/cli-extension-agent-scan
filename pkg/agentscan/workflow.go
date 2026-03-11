package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.4.5"

	AgentScanBinaryChecksumLinuxAmd64 = "970117704e6339288ed62e897a05920b6db23dffeea7d3f04605f273534df8b0"
	AgentScanBinaryChecksumMacOSArm64 = "e2f2cb9dc38c3affed9ca2c2628ed0aac191b8d7d9bab75c200c14839a50c555"
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
