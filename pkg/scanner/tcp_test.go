package scanner

import (
	"context"
	"testing"
	"time"
)

func TestTCPScan(t *testing.T) {
	ctx := context.Background()
	result := TCPScan(ctx, "127.0.0.1", 22, 2*time.Second)

	if result.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", result.Host)
	}
	if result.Port != 22 {
		t.Errorf("expected port 22, got %d", result.Port)
	}
	if result.Latency <= 0 {
		t.Error("expected positive latency")
	}
}

func TestTCPScanClosed(t *testing.T) {
	ctx := context.Background()
	result := TCPScan(ctx, "127.0.0.1", 1, 1*time.Second)

	if result.State != "closed" && result.State != "filtered" {
		t.Errorf("expected closed or filtered state, got %s", result.State)
	}
}
