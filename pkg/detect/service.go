package detect

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var serviceMap = map[int]string{
	20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
	25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
	111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
	143: "IMAP", 443: "HTTPS", 445: "SMB",
	993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
	1521: "Oracle", 1723: "PPTP", 2049: "NFS",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5900: "VNC", 6379: "Redis", 64680: "RDP",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Proxy",
	9090: "HTTP-Admin", 9200: "Elasticsearch", 9300: "Elasticsearch",
	11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
	50000: "SAP", 50070: "HDFS",
}

type ServiceInfo struct {
	Name    string
	Version string
	Banner  string
}

func DetectService(host string, port int, timeout time.Duration) *ServiceInfo {
	info := &ServiceInfo{
		Name: LookupServiceName(port),
	}

	banner := grabBanner(host, port, timeout)
	if banner == "" {
		return info
	}

	info.Banner = banner
	info.Version = extractVersion(info.Name, banner)
	return info
}

func grabBanner(host string, port int, timeout time.Duration) string {
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	if port == 80 || port == 8080 || port == 8888 || port == 9090 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return ""
	}

	return strings.TrimSpace(string(buf[:n]))
}

func extractVersion(serviceName, banner string) string {
	if banner == "" {
		return ""
	}

	switch serviceName {
	case "SSH":
		if strings.HasPrefix(banner, "SSH-") {
			parts := strings.Split(banner, " ")
			if len(parts) >= 1 {
				return parts[0]
			}
		}
	case "HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt":
		lines := strings.Split(banner, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line[7:])
			}
		}
		if strings.Contains(banner, "HTTP/") {
			idx := strings.Index(banner, "HTTP/")
			if idx >= 0 {
				end := idx + 12
				if end > len(banner) {
					end = len(banner)
				}
				return banner[idx:end]
			}
		}
	case "MySQL":
		if idx := strings.Index(banner, "mysql"); idx >= 0 {
			return banner[idx:]
		}
	case "Redis":
		lines := strings.Split(banner, "\r\n")
		if len(lines) > 0 {
			return lines[0]
		}
	}

	lines := strings.Split(banner, "\n")
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		if len(firstLine) > 0 && len(firstLine) < 128 {
			return firstLine
		}
	}

	return ""
}

func LookupServiceName(port int) string {
	if name, ok := serviceMap[port]; ok {
		return name
	}
	return "unknown"
}
