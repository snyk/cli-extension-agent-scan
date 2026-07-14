package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.5.13"

	AgentScanBinaryChecksumLinuxAmd64   = "8e605ee8426edd2acced0adb8305b38cfc3ff3f07204d80a370d6a77f21b20bd"
	AgentScanBinaryChecksumLinuxArm64   = "9aac9cd948c798a03445e7490b193c2e504021bd6d7edc42178afc2a3b282d3b"
	AgentScanBinaryChecksumMacOSArm64   = "7907e46c89c399c0d91e09707e637733591e2b2f4cec1c2130874ccf147d6745"
	AgentScanBinaryChecksumMacOSIntel   = "1ca8b7e42b17feb2de6f1584ee62b694e64b57f28f588bc094c54ed6081c7a14"
	AgentScanBinaryChecksumWindowsAmd64 = "4bc78ba892767628cfa4e1b52b0a8de94caa0484f424ff1b6f34d20cca55fc6d"
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
