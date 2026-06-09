package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ivoidable/vscan/pkg/netutil"
	"github.com/ivoidable/vscan/pkg/output"
	"github.com/ivoidable/vscan/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	ports         string
	scanType      string
	outputFmt     string
	outputFile    string
	workers       int
	timeout       time.Duration
	serviceDetect bool
	noPing        bool
	iface         string
)

var scanCmd = &cobra.Command{
	Use:   "scan [hosts...]",
	Short: "Scan target hosts for open ports",
	Long: `Scan one or more hosts for open ports.

Examples:
  vscan scan 192.168.1.1
  vscan scan 192.168.1.1 -p 80,443,8080
  vscan scan 192.168.1.1 -p 1-1024 --scan syn --iface eth0
  vscan scan 192.168.1.0/24 -p 80,443 --output json
  vscan scan example.com -p 22,80,443 --service-detect`,
	Args: cobra.MinimumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "top100", "Port specification (e.g., 80,443 1-1024 1-65535)")
	scanCmd.Flags().StringVar(&scanType, "scan", "tcp", "Scan type: tcp, syn")
	scanCmd.Flags().StringVarP(&outputFmt, "output", "o", "cli", "Output format: cli, json, csv")
	scanCmd.Flags().StringVar(&outputFile, "out", "", "Write results to file")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 100, "Number of concurrent workers")
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", 2*time.Second, "Per-port timeout")
	scanCmd.Flags().BoolVar(&serviceDetect, "service-detect", false, "Enable service detection and banner grabbing")
	scanCmd.Flags().BoolVar(&noPing, "no-ping", false, "Skip host discovery")
	scanCmd.Flags().StringVar(&iface, "iface", "", "Network interface for SYN scan (e.g., eth0, en0)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var allHosts []string
	for _, arg := range args {
		hosts, err := netutil.ExpandHosts(arg)
		if err != nil {
			return fmt.Errorf("invalid host %q: %w", arg, err)
		}
		allHosts = append(allHosts, hosts...)
	}

	var portList []int
	if ports == "top100" {
		portList = netutil.TopPorts(100)
	} else if ports == "top1000" {
		portList = netutil.TopPorts(1000)
	} else {
		var err error
		portList, err = netutil.ParsePorts(ports)
		if err != nil {
			return fmt.Errorf("invalid port specification: %w", err)
		}
	}

	cfg := &scanner.ScanConfig{
		Hosts:         allHosts,
		Ports:         portList,
		ScanType:      scanner.ScanType(scanType),
		Workers:       workers,
		Timeout:       timeout,
		ServiceDetect: serviceDetect,
		SkipPing:      noPing,
	}

	fmt.Fprintf(os.Stderr, "vscan - Fast Port Scanner\n")
	fmt.Fprintf(os.Stderr, "Target: %s | Ports: %d | Workers: %d | Timeout: %s\n",
		strings.Join(allHosts, ", "), len(portList), workers, timeout)
	fmt.Fprintf(os.Stderr, "Scan type: %s | Service detect: %v\n\n", scanType, serviceDetect)

	var results []scanner.ScanResult
	var err error

	if scanType == "syn" {
		if iface == "" {
			iface = getDefaultInterface()
		}
		fmt.Fprintf(os.Stderr, "Using SYN scan on interface %s (requires root)\n", iface)
		results, err = scanner.RunSYN(ctx, cfg, iface)
	} else {
		results, err = scanner.Run(ctx, cfg)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	switch outputFmt {
	case "json":
		if outputFile != "" {
			f, ferr := os.Create(outputFile)
			if ferr != nil {
				return fmt.Errorf("failed to create output file: %w", ferr)
			}
			defer f.Close()
			return output.WriteJSON(results, f)
		}
		return output.WriteJSON(results, os.Stdout)

	case "csv":
		if outputFile != "" {
			f, ferr := os.Create(outputFile)
			if ferr != nil {
				return fmt.Errorf("failed to create output file: %w", ferr)
			}
			defer f.Close()
			return output.WriteCSV(results, f)
		}
		return output.WriteCSV(results, os.Stdout)

	default:
		output.WriteCLI(results, os.Stdout)
		output.WriteSummary(results, os.Stderr)
	}

	return nil
}

func getDefaultInterface() string {
	for _, name := range []string{"eth0", "en0", "en1", "wlan0"} {
		if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", name)); err == nil {
			return name
		}
	}
	return "en0"
}
