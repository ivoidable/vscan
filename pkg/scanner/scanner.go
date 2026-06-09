package scanner

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/ivoidable/vscan/pkg/detect"
)

func Run(ctx context.Context, cfg *ScanConfig) ([]ScanResult, error) {
	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("no hosts to scan")
	}
	if len(cfg.Ports) == 0 {
		return nil, fmt.Errorf("no ports to scan")
	}

	if !cfg.SkipPing {
		alive := discoverHosts(ctx, cfg.Hosts, cfg.Timeout)
		if len(alive) == 0 {
			return nil, fmt.Errorf("no hosts responded to ping")
		}
		cfg.Hosts = alive
	}

	var results []ScanResult
	var mu sync.Mutex
	jobs := make(chan scanJob, len(cfg.Hosts)*len(cfg.Ports))
	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 10
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result := TCPScan(ctx, job.host, job.port, cfg.Timeout)

				if result.State == "open" && cfg.ServiceDetect {
					svc := detect.DetectService(job.host, job.port, cfg.Timeout)
					result.Service = svc.Name
					result.Banner = svc.Banner
				} else if result.State == "open" {
					result.Service = detect.LookupServiceName(job.port)
				}

				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}()
	}

	for _, host := range cfg.Hosts {
		for _, port := range cfg.Ports {
			jobs <- scanJob{host: host, port: port}
		}
	}
	close(jobs)

	wg.Wait()
	return results, nil
}

type scanJob struct {
	host string
	port int
}

func RunSYN(ctx context.Context, cfg *ScanConfig, ifaceName string) ([]ScanResult, error) {
	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("no hosts to scan")
	}
	if len(cfg.Ports) == 0 {
		return nil, fmt.Errorf("no ports to scan")
	}

	var results []ScanResult
	var mu sync.Mutex

	for _, host := range cfg.Hosts {
		scanner, err := NewSYNScanner(host, ifaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize SYN scanner for %s: %w", host, err)
		}

		jobs := make(chan int, len(cfg.Ports))
		workers := cfg.Workers
		if workers <= 0 {
			workers = runtime.NumCPU() * 10
		}

		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for port := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}

					result := scanner.Scan(ctx, host, port, cfg.Timeout)

					if result.State == "open" && cfg.ServiceDetect {
						svc := detect.DetectService(host, port, cfg.Timeout)
						result.Service = svc.Name
						result.Banner = svc.Banner
					} else if result.State == "open" {
						result.Service = detect.LookupServiceName(port)
					}

					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}()
		}

		for _, port := range cfg.Ports {
			jobs <- port
		}
		close(jobs)
		wg.Wait()
		scanner.Close()
	}

	return results, nil
}

func discoverHosts(ctx context.Context, hosts []string, timeout time.Duration) []string {
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			if isAlive(ctx, h, timeout) {
				mu.Lock()
				alive = append(alive, h)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	return alive
}

func isAlive(ctx context.Context, host string, timeout time.Duration) bool {
	for _, port := range []int{80, 443, 22, 135, 445, 3389} {
		result := TCPScan(ctx, host, port, timeout/3)
		if result.State == "open" {
			return true
		}
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), timeout/3)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}
