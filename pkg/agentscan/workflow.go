package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.4.6"

	AgentScanBinaryChecksumLinuxAmd64 = "e0750a35d6e1dce2574e602046e1085ccbed5072f80ce5e240fc30e6434af139"
	AgentScanBinaryChecksumMacOSArm64 = "26af48d4467e4d91b31760a83d7e4323bd0cbd4bb984780338005c56f512f5ba"
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
