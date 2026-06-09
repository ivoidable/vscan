package defaults

import "time"

const (
	DefaultTimeout  = 2 * time.Second
	DefaultWorkers  = 100
	DefaultScanType = "tcp"
	DefaultOutput   = "cli"
)
