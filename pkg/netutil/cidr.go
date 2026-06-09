package netutil

import (
	"fmt"
	"net"
)

func ExpandHosts(spec string) ([]string, error) {
	if ip := net.ParseIP(spec); ip != nil {
		return []string{spec}, nil
	}

	_, network, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid host or CIDR %q: %w", spec, err)
	}

	var hosts []string
	for ip := cloneIP(network.IP); network.Contains(ip); incIP(ip) {
		ones, bits := network.Mask.Size()
		if ones < bits {
			if ip.Equal(network.IP) {
				incIP(ip)
				continue
			}
			broadcast := cloneIP(network.IP)
			for j := range broadcast {
				broadcast[j] = network.IP[j] | ^network.Mask[j]
			}
			if ip.Equal(broadcast) {
				break
			}
		}
		hosts = append(hosts, ip.String())
	}

	return hosts, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
