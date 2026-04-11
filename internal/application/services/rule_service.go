package services

import (
	"io"

	"github.com/netxfw/netxfw/internal/app"
	"github.com/netxfw/netxfw/internal/application/ports"
	"github.com/netxfw/netxfw/pkg/sdk"
)

// RuleService is the application-layer entry for rule import/export flows.
type RuleService struct {
	gateway ports.ConfigGateway
}

func NewRuleService(gateway ports.ConfigGateway) *RuleService {
	return &RuleService{gateway: gateway}
}

func (s *RuleService) ImportStructured(w io.Writer, fw *sdk.SDK, filePath string, isJSON bool) error {
	return app.ImportFromStructuredFile(w, fw, filePath, isJSON)
}

func (s *RuleService) ImportBinary(w io.Writer, fw *sdk.SDK, filePath string) error {
	return app.ImportFromBinaryFile(w, fw, filePath)
}

func (s *RuleService) ExportStructured(w io.Writer, fw *sdk.SDK, filePath, format string) error {
	return app.ExportToStructuredFile(w, fw, filePath, format)
}

func (s *RuleService) ExportCSV(w io.Writer, fw *sdk.SDK, filePath string) error {
	return app.ExportToCSVFile(w, fw, filePath)
}

func (s *RuleService) ExportBinary(w io.Writer, fw *sdk.SDK, filePath string) error {
	return app.ExportToBinaryFile(w, fw, filePath)
}
