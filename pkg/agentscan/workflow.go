package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.4.18"

	AgentScanBinaryChecksumLinuxAmd64   = "b7ee9068e7e81eb6f8e343faa839f05ca00a354b85081b09a1fdcaa6faa2cbab"
	AgentScanBinaryChecksumMacOSArm64   = "4095416649e6241ea4785263a627cf6bc7a17fd5a18274ae25e21b2293d8a71a"
	AgentScanBinaryChecksumMacOSIntel   = "844766ecc7947f4de5062dc50a385843e3e0def07e09e88944840fd102682213"
	AgentScanBinaryChecksumWindowsAmd64 = "7bf04fcfdab917194ac45f0faca5aef17d666b27978d3f46ece772156577e006"
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
