package netutil

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{name: "single port", input: "80", want: []int{80}},
		{name: "multiple ports", input: "80,443,8080", want: []int{80, 443, 8080}},
		{name: "port range", input: "1-5", want: []int{1, 2, 3, 4, 5}},
		{name: "mixed", input: "80,443,1000-1003", want: []int{80, 443, 1000, 1001, 1002, 1003}},
		{name: "dedup", input: "80,80,80", want: []int{80}},
		{name: "invalid port", input: "abc", wantErr: true},
		{name: "port too high", input: "70000", wantErr: true},
		{name: "start > end", input: "100-50", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePorts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePorts(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExpandHosts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{name: "single IP", input: "192.168.1.1", want: []string{"192.168.1.1"}},
		{name: "invalid", input: "not-an-ip", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandHosts(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandHosts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExpandHosts(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTopPorts(t *testing.T) {
	ports := TopPorts(10)
	if len(ports) != 10 {
		t.Errorf("TopPorts(10) returned %d ports, want 10", len(ports))
	}
	for i := 1; i < len(ports); i++ {
		if ports[i] < ports[i-1] {
			t.Errorf("TopPorts not sorted: %v", ports)
			break
		}
	}
}
