package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SYNScanner struct {
	handle *pcap.Handle
	srcIP  net.IP
	srcMAC net.HardwareAddr
	dstIP  net.IP
	dstMAC net.HardwareAddr
	iface  *net.Interface
	opts   gopacket.SerializeOptions
	buf    gopacket.SerializeBuffer
}

func NewSYNScanner(targetIP string, ifaceName string) (*SYNScanner, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	srcIP, err := getLocalIP(iface)
	if err != nil {
		return nil, fmt.Errorf("could not determine local IP: %w", err)
	}

	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", targetIP)
	}

	gateway, err := getGateway()
	if err != nil {
		return nil, fmt.Errorf("could not determine gateway: %w", err)
	}

	handle, err := pcap.OpenLive(ifaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("could not open pcap: %w", err)
	}

	dstMAC, err := resolveMAC(dstIP, gateway, iface)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("could not resolve destination MAC: %w", err)
	}

	scanner := &SYNScanner{
		handle: handle,
		srcIP:  srcIP,
		srcMAC: iface.HardwareAddr,
		dstIP:  dstIP,
		dstMAC: dstMAC,
		iface:  iface,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	return scanner, nil
}

func (s *SYNScanner) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *SYNScanner) Scan(ctx context.Context, host string, port int, timeout time.Duration) ScanResult {
	start := time.Now()
	result := ScanResult{
		Host:  host,
		Port:  port,
		State: "filtered",
	}

	if err := s.sendSYN(layers.TCPPort(port)); err != nil {
		result.State = "filtered"
		result.Latency = time.Since(start)
		return result
	}

	state := s.waitForResponse(timeout)
	result.State = state
	result.Latency = time.Since(start)
	return result
}

func (s *SYNScanner) sendSYN(dstPort layers.TCPPort) error {
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rand.Intn(65535-1024) + 1024),
		DstPort: dstPort,
		SYN:     true,
		Seq:     rand.Uint32(),
		Window:  14600,
	}

	ip4 := layers.IPv4{
		SrcIP:    s.srcIP,
		DstIP:    s.dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp.SetNetworkLayerForChecksum(&ip4)

	eth := layers.Ethernet{
		SrcMAC:       s.srcMAC,
		DstMAC:       s.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	if err := s.buf.Clear(); err != nil {
		return err
	}

	if err := gopacket.SerializeLayers(s.buf, s.opts, &eth, &ip4, &tcp); err != nil {
		return err
	}

	return s.handle.WritePacketData(s.buf.Bytes())
}

func (s *SYNScanner) waitForResponse(timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	for {
		if time.Now().After(deadline) {
			return "filtered"
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			continue
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil {
			continue
		}

		if tcp.SYN && tcp.ACK {
			return "open"
		}
		if tcp.RST {
			return "closed"
		}
	}
}

func getLocalIP(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.To4(), nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address found on interface %s", iface.Name)
}

func getGateway() (net.IP, error) {
	f, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	localAddr := f.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

func resolveMAC(targetIP, gateway net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	arpTarget := targetIP
	if !sameSubnet(targetIP, gateway, iface) {
		arpTarget = gateway
	}
	return arpLookup(arpTarget, iface)
}

func sameSubnet(a, b net.IP, iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.Contains(a) && ipNet.Contains(b) {
				return true
			}
		}
	}
	return false
}

func arpLookup(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	f, err := net.Dial("udp", fmt.Sprintf("%s:53", ip.String()))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return iface.HardwareAddr, nil
}
