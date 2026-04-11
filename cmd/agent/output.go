package agent

import (
	"fmt"

	"github.com/spf13/cobra"
)

func printInfof(cmd *cobra.Command, format string, args ...any) {
	cmd.Println(fmt.Sprintf(format, args...))
}
