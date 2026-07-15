package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.5.14"

	AgentScanBinaryChecksumLinuxAmd64   = "ce5dbdd147c347864f6cc4df01cb35e18fe8b787b9e5a205e35a9217e2f79f26"
	AgentScanBinaryChecksumLinuxArm64   = "510b711ae66c5504ab19882701cf5b2b37ccc1e1a1fb1f2fe3efd7680fc8137d"
	AgentScanBinaryChecksumMacOSArm64   = "e1db08edf7c5465b100896679a72b0cca701645c2adf02879d39dc7028658bb4"
	AgentScanBinaryChecksumMacOSIntel   = "f9f62b5650f425b8202a674452f171995d4928544778b970dfc836bad8773828"
	AgentScanBinaryChecksumWindowsAmd64 = "a17ec3d8649105eeff78fb9409124d9609c69187d7b5ab0b52fd7d702e0ecd60"
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
