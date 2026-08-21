package agentscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "agent-scan"

	AgentScanBinaryVersion = "0.6.0"

	AgentScanBinaryChecksumLinuxAmd64   = "0e0833017f118150b922e528076ede972b746640567fc4b0cacb2e67054fb8d4"
	AgentScanBinaryChecksumLinuxArm64   = "c9f4cdf9d90d8e7310f51b122e7a699de6cd777c29813b1fd96aeafc00cea44a"
	AgentScanBinaryChecksumMacOSArm64   = "3bfe02c44f37266983dd83c87805d70df5a9812f41e9af308e443a1934ef5212"
	AgentScanBinaryChecksumMacOSIntel   = "13f957c3ba223a36b17b643adea052aa2bf5824e440cc4b8d7446b3b78821d29"
	AgentScanBinaryChecksumWindowsAmd64 = "8ed694caaaa22724357543130fda048984a975c5c9e7a3ff6837307e344b3a2c"
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
