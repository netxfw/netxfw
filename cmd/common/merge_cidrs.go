package common

import (
	"fmt"
	"strings"

	"github.com/netxfw/netxfw/internal/utils/ipmerge"
	"github.com/spf13/cobra"
)

var MergeCIDRsCmd = &cobra.Command{
	Use:   "merge-cidrs <cidr1> <cidr2> ...",
	Short: "Merge adjacent/overlapping CIDR ranges",
	Long: `Merge a list of CIDR ranges into a minimal set of non-overlapping ranges.
合并一组 CIDR 网段为最小化的不重叠网段列表。

Supports both IPv4 and IPv6 CIDR notation. Invalid CIDRs are silently ignored.
支持 IPv4 和 IPv6 CIDR 格式，无效 CIDR 会被忽略。

Examples:
  netxfw merge-cidrs 10.0.0.0/24 10.0.0.128/25
  netxfw merge-cidrs 192.168.0.0/24 192.168.1.0/24 192.168.2.0/24
  netxfw merge-cidrs 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24 --threshold 3 --v4-mask 16`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		threshold, _ := cmd.Flags().GetInt("threshold")
		v4Mask, _ := cmd.Flags().GetInt("v4-mask")
		v6Mask, _ := cmd.Flags().GetInt("v6-mask")

		var result []string
		var err error

		if threshold > 1 {
			result, err = ipmerge.MergeCIDRsWithThreshold(args, threshold, v4Mask, v6Mask)
		} else {
			result, err = ipmerge.MergeCIDRs(args)
		}
		if err != nil {
			return err
		}

		fmt.Println(strings.Join(result, "\n"))
		return nil
	},
}

func init() {
	MergeCIDRsCmd.Flags().Int("threshold", 0, "Promote to parent subnet when count >= threshold (0=disabled)")
	MergeCIDRsCmd.Flags().Int("v4-mask", 24, "Parent mask for IPv4 promotion")
	MergeCIDRsCmd.Flags().Int("v6-mask", 64, "Parent mask for IPv6 promotion")
}
