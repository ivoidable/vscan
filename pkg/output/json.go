package output

import (
	"encoding/json"
	"io"

	"github.com/ivoidable/vscan/pkg/scanner"
)

func WriteJSON(results []scanner.ScanResult, w io.Writer) error {
	output := struct {
		Count   int                  `json:"count"`
		Results []scanner.ScanResult `json:"results"`
	}{
		Count:   len(results),
		Results: results,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
