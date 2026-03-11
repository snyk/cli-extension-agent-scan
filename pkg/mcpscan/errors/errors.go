package errors

import (
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// AgentScanError is a wrapper around snyk_errors to abstract & enable greater control of errors within this repository.
type AgentScanError struct {
	SnykError snyk_errors.Error
}

func NewUnauthorizedError(msg string) *AgentScanError {
	return &AgentScanError{SnykError: snyk_common_errors.NewUnauthorisedError(msg)}
}

func NewCommandIsExperimentalError() *AgentScanError {
	return &AgentScanError{SnykError: cli_errors.NewCommandIsExperimentalError("Snyk agent-scan is experimental and likely to change.")}
}

func NewInvalidTenantIDError() *AgentScanError {
	return &AgentScanError{SnykError: snyk_common_errors.NewUnauthorisedError("Invalid tenant ID")}
}

func NewInvalidClientIDError() *AgentScanError {
	return &AgentScanError{SnykError: snyk_common_errors.NewUnauthorisedError("Invalid client ID")}
}
