package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.5.1"

	AgentScanBinaryChecksumLinuxAmd64   = "99153ef8390ba4486e2785f5bc18f2ce15924c6104ec2c7571ccb969ce8d3a2d"
	AgentScanBinaryChecksumMacOSArm64   = "5980072646792e1de5a1621ba4556e0cd28fc9f1614d05875958e4b1d814434e"
	AgentScanBinaryChecksumMacOSIntel   = "3a82ab38cddbd1c8698322f9dbff8dd6531aa5e7ae0fbd7a088af13206dc693f"
	AgentScanBinaryChecksumWindowsAmd64 = "d6f65c662939035c76743c3a376c3b43dd5522226d95cf6216d4a46e682f58e1"
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
