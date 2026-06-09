package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

func TCPScan(ctx context.Context, host string, port int, timeout time.Duration) ScanResult {
	start := time.Now()
	result := ScanResult{
		Host:  host,
		Port:  port,
		State: "filtered",
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = "filtered"
		} else {
			result.State = "closed"
		}
		result.Latency = time.Since(start)
		return result
	}
	conn.Close()

	result.State = "open"
	result.Latency = time.Since(start)
	return result
}
