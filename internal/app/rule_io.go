package app

import (
	"io"

	apprule "github.com/netxfw/netxfw/internal/app/rule"
	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/pkg/sdk"
)

func ImportFromStructuredFile(w io.Writer, s *sdk.SDK, filePath string, isJSON bool) error {
	return apprule.ImportStructured(w, s, filePath, isJSON)
}

func ExportToStructuredFile(w io.Writer, s *sdk.SDK, filePath, format string) error {
	return apprule.ExportStructured(w, config.DefaultWriteGateway(), s, filePath, format)
}

func ExportToCSVFile(w io.Writer, s *sdk.SDK, filePath string) error {
	return apprule.ExportCSV(w, config.DefaultWriteGateway(), s, filePath)
}

func ImportFromBinaryFile(w io.Writer, s *sdk.SDK, filePath string) error {
	return apprule.ImportBinary(w, s, filePath)
}

func ExportToBinaryFile(w io.Writer, s *sdk.SDK, filePath string) error {
	return apprule.ExportBinary(w, s, filePath)
}
