package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jingkaihe/matchlock/pkg/lifecycle"
	"github.com/jingkaihe/matchlock/pkg/state"
)

var gcCmd = &cobra.Command{
	Use:   "gc [vm-id]",
	Short: "Reconcile leaked VM host resources",
	Long:  "Reconcile leaked VM host resources (TAP/nftables/subnet/rootfs) using lifecycle records.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGC,
}

func init() {
	gcCmd.Flags().Bool("force-running", false, "Also reconcile VMs that are currently running")
	gcCmd.Flags().Int("prune-events-days", 0, "Delete events older than N days (0 = skip)")
	rootCmd.AddCommand(gcCmd)
}

func runGC(cmd *cobra.Command, args []string) error {
	forceRunning, _ := cmd.Flags().GetBool("force-running")
	pruneEventsDays, _ := cmd.Flags().GetInt("prune-events-days")
	reconciler := lifecycle.NewReconciler()

	if len(args) == 1 {
		report, err := reconciler.ReconcileVM(args[0], forceRunning)
		printGCReport(report)
		return err
	}

	reports, err := reconciler.ReconcileAll(forceRunning)
	for _, report := range reports {
		printGCReport(report)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Reconciled %d VMs\n", len(reports))

	if pruneEventsDays > 0 {
		mgr := state.NewManager()
		deleted, err := mgr.PruneEvents(pruneEventsDays)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to prune events: %v\n", err)
		} else if deleted > 0 {
			fmt.Printf("Pruned %d events older than %d days\n", deleted, pruneEventsDays)
		}
	}

	return nil
}

func printGCReport(report lifecycle.ReconcileReport) {
	if report.Skipped != "" {
		fmt.Printf("%s: skipped (%s)\n", report.VMID, report.Skipped)
		return
	}

	if len(report.Cleaned) > 0 {
		sort.Strings(report.Cleaned)
		fmt.Printf("%s: cleaned %s\n", report.VMID, strings.Join(report.Cleaned, ", "))
	} else {
		fmt.Printf("%s: no resources to clean\n", report.VMID)
	}

	if len(report.Failed) > 0 {
		keys := make([]string, 0, len(report.Failed))
		for k := range report.Failed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(os.Stderr, "%s: failed %s: %s\n", report.VMID, k, report.Failed[k])
		}
	}
}
