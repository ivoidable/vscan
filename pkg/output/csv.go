package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/ivoidable/vscan/pkg/scanner"
)

func WriteCSV(results []scanner.ScanResult, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{"host", "port", "state", "service", "banner", "latency_ms"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, r := range results {
		record := []string{
			r.Host,
			strconv.Itoa(r.Port),
			r.State,
			r.Service,
			r.Banner,
			fmt.Sprintf("%.1f", float64(r.Latency.Microseconds())/1000.0),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	return nil
}
