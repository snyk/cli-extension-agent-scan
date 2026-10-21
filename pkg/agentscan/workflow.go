package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.6.9"

	AgentScanBinaryChecksumLinuxAmd64   = "81197269da1e1a272400e58e417ea5ae55ad7d9c68a6396fb9eb6139bf146d6e"
	AgentScanBinaryChecksumLinuxArm64   = "5b0d9cb7685fd36c3cb57f8e295afa8b28462ebc0e8e3f468fdf9f6f53c8652e"
	AgentScanBinaryChecksumMacOSArm64   = "93de410f0e3c19a1fe45dcb1fbc0c20ed570137747c1d594702bad83d7e84658"
	AgentScanBinaryChecksumMacOSIntel   = "4ba5b303cc623b03f095ea84bbaf79a3a5fc7d8999857fee19076ebd82c61770"
	AgentScanBinaryChecksumWindowsAmd64 = "5ed48e9b0a29118d439b3d872ae81d7635c6acf99d0ad09c63a4e7beff40eae4"
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
