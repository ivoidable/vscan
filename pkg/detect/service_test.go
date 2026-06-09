package detect

import (
	"testing"
)

func TestLookupServiceName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{80, "HTTP"},
		{443, "HTTPS"},
		{22, "SSH"},
		{3306, "MySQL"},
		{99999, "unknown"},
	}

	for _, tt := range tests {
		got := LookupServiceName(tt.port)
		if got != tt.want {
			t.Errorf("LookupServiceName(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}
