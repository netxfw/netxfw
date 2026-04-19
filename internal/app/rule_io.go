package app

import (
	"io"

	appconfig "github.com/netxfw/netxfw/internal/app/config"
	apprule "github.com/netxfw/netxfw/internal/app/rule"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
)

func ImportFromStructuredFile(w io.Writer, s *sdk.SDK, filePath string, isJSON bool) error {
	return apprule.ImportStructured(w, s, filePath, isJSON)
}

func ExportToStructuredFile(w io.Writer, s *sdk.SDK, filePath, format string) error {
	return apprule.ExportStructured(w, appconfig.DefaultWriteGateway(), s, filePath, format)
}

func ExportToCSVFile(w io.Writer, s *sdk.SDK, filePath string) error {
	return apprule.ExportCSV(w, appconfig.DefaultWriteGateway(), s, filePath)
}

func ImportFromBinaryFile(w io.Writer, s *sdk.SDK, filePath string) error {
	return apprule.ImportBinary(w, s, filePath)
}

func ExportToBinaryFile(w io.Writer, s *sdk.SDK, filePath string) error {
	return apprule.ExportBinary(w, s, filePath)
}
