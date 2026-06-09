package scanner

import "time"

type ScanType string

const (
	TCP ScanType = "tcp"
	SYN ScanType = "syn"
)

type ScanConfig struct {
	Hosts         []string
	Ports         []int
	ScanType      ScanType
	Workers       int
	Timeout       time.Duration
	ServiceDetect bool
	SkipPing      bool
}

type ScanResult struct {
	Host    string        `json:"host" csv:"host"`
	Port    int           `json:"port" csv:"port"`
	State   string        `json:"state" csv:"state"`
	Service string        `json:"service" csv:"service"`
	Banner  string        `json:"banner,omitempty" csv:"banner"`
	Latency time.Duration `json:"latency" csv:"latency_ms"`
}
