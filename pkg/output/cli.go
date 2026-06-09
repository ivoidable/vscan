package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ivoidable/vscan/pkg/scanner"
)

func WriteCLI(results []scanner.ScanResult, w io.Writer) {
	open := filterOpen(results)

	if len(open) == 0 {
		fmt.Fprintln(w, "No open ports found.")
		return
	}

	sort.Slice(open, func(i, j int) bool {
		if open[i].Host != open[j].Host {
			return open[i].Host < open[j].Host
		}
		return open[i].Port < open[j].Port
	})

	fmt.Fprintf(w, "\nScan Results (%d open port(s))\n", len(open))
	fmt.Fprintln(w, strings.Repeat("─", 80))
	fmt.Fprintf(w, "%-16s  %-6s  %-10s  %-12s  %s\n", "HOST", "PORT", "STATE", "SERVICE", "LATENCY")
	fmt.Fprintln(w, strings.Repeat("─", 80))

	for _, r := range open {
		latency := fmt.Sprintf("%.1fms", float64(r.Latency.Microseconds())/1000.0)
		service := r.Service
		if r.Banner != "" && len(r.Banner) > 30 {
			service = r.Banner[:30] + "..."
		} else if r.Banner != "" {
			service = r.Banner
		}

		fmt.Fprintf(w, "%-16s  %-6d  %-10s  %-12s  %s\n",
			r.Host, r.Port, r.State, service, latency)
	}
	fmt.Fprintln(w, strings.Repeat("─", 80))

	hosts := make(map[string]int)
	for _, r := range open {
		hosts[r.Host]++
	}

	fmt.Fprintf(w, "\nSummary: %d host(s), %d open port(s)\n", len(hosts), len(open))
}

func WriteSummary(results []scanner.ScanResult, w io.Writer) {
	total := len(results)
	open := 0
	closed := 0
	filtered := 0

	for _, r := range results {
		switch r.State {
		case "open":
			open++
		case "closed":
			closed++
		case "filtered":
			filtered++
		}
	}

	elapsed := time.Duration(0)
	for _, r := range results {
		elapsed += r.Latency
	}

	fmt.Fprintf(w, "\nScan complete: %d total, %d open, %d closed, %d filtered\n",
		total, open, closed, filtered)
	fmt.Fprintf(w, "Total scan time: %s\n\n", elapsed.Round(time.Millisecond))
}

func filterOpen(results []scanner.ScanResult) []scanner.ScanResult {
	var open []scanner.ScanResult
	for _, r := range results {
		if r.State == "open" {
			open = append(open, r)
		}
	}
	return open
}
