package netutil

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func ParsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	var ports []int

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port %q: %w", bounds[0], err)
			}

			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port %q: %w", bounds[1], err)
			}

			if start < 1 || start > 65535 {
				return nil, fmt.Errorf("start port %d out of range (1-65535)", start)
			}
			if end < 1 || end > 65535 {
				return nil, fmt.Errorf("end port %d out of range (1-65535)", end)
			}
			if start > end {
				return nil, fmt.Errorf("start port %d > end port %d", start, end)
			}

			for i := start; i <= end; i++ {
				if !seen[i] {
					seen[i] = true
					ports = append(ports, i)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", part, err)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port %d out of range (1-65535)", p)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	sort.Ints(ports)
	return ports, nil
}

func TopPorts(n int) []int {
	top := []int{
		80, 443, 22, 21, 25, 53, 110, 143, 993, 995,
		3389, 3306, 5432, 6379, 8080, 8443, 8888, 27017,
		1433, 1521, 5900, 8000, 9090, 9200, 9300, 11211,
		27018, 49152, 49153, 49154, 49155, 135, 139, 445, 389,
		636, 88, 464, 514, 161, 162, 123, 5060, 5061,
		5601, 9093, 2181, 6667, 6697, 5222,
		5223, 5269, 1883, 8883, 4443, 1434, 2433,
		4333, 4334, 3050, 3051, 4335, 1583, 4336, 50000,
		50070, 60000, 60010, 60020, 60030, 64680, 64690, 65530,
	}

	if n > len(top) {
		n = len(top)
	}

	seen := make(map[int]bool)
	var result []int
	for _, p := range top {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
		if len(result) >= n {
			break
		}
	}
	sort.Ints(result)
	return result
}
