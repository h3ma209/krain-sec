package main

import (
	"context"
	"fmt"
	"krain-sec/mitm"
	"krain-sec/utils"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	// "strings"
	"time"

	"github.com/google/gopacket/pcap"
)

type Config struct {
	InterfaceName string
	Timeout       time.Duration
	IpBase        string
	SourceIP      net.IP
}

type Scanner struct {
	config Config
	handle *pcap.Handle
	iface  *net.Interface
}

func NewScanner(interfaceName string) (*Scanner, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("Failed to get Interface %s: %w", interfaceName, err)
	}

	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)

	if err != nil {
		return nil, fmt.Errorf("Failed to open pcap handle: %w", err)
	}

	config := Config{
		InterfaceName: interfaceName,
		Timeout:       5 * time.Second,
	}
	if err := setIPConfig(&config, iface); err != nil {
		handle.Close()
		return nil, err
	}

	return &Scanner{
		config: config,
		handle: handle,
		iface:  iface,
	}, nil
}

func (s *Scanner) displayResults(clients []utils.NetworkClient) {
	fmt.Println("\nDiscovered devices:")
	fmt.Println("| IP Address\t\t | MAC Address\t\t |")
	fmt.Println("|------------------------|-------------------|")

	for _, c := range clients {
		fmt.Printf("| %-20s | %-17s |\n", c.IpAddress, c.MacAddress)
	}
	fmt.Printf("Total devices: %d\n\n", len(clients))
}
func setIPConfig(config *Config, iface *net.Interface) error {
	addrs, err := iface.Addrs()

	if err != nil {
		return fmt.Errorf("failed to adddress for the interface %s: %w", config.InterfaceName, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			ipv4 := ipNet.IP.To4()
			config.SourceIP = ipv4

			network := ipNet.IP.Mask(ipNet.Mask)
			if netv4 := network.To4(); netv4 != nil {
				config.IpBase = fmt.Sprintf("%d.%d.%d", netv4[0], netv4[1], netv4[2])
			}
			break
		}
	}

	if config.SourceIP == nil {
		return fmt.Errorf("no valid ipv4 %s", config.InterfaceName)
	}
	return nil
}

func (s *Scanner) Scan(ctx context.Context) ([]utils.NetworkClient, error) {
	return mitm.ScanARP(s.handle, s.iface, s.config.IpBase, s.config.SourceIP, s.config.Timeout)
}

func (s *Scanner) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}

func main() {

	utils.Banner()
	scanner, err := NewScanner("wlo1")
	if err != nil {
		log.Fatalf("Failed to create Scanner", err)
	}

	defer scanner.Close()
	fmt.Printf("Using interface: %s (%s)\n", scanner.iface.Name, scanner.iface.HardwareAddr)
	fmt.Printf("Using IP base: %s\n", scanner.config.IpBase)
	fmt.Printf("Using IP source: %s\n", scanner.config.SourceIP)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n Received Interrupt signal shutting down")
		cancel()
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	if clients, err := scanner.Scan(ctx); err != nil {
		log.Printf("Scan Error : %v", err)
	} else {
		scanner.displayResults(clients)
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Scanner Stopped")
			return
		case <-ticker.C:
			clients, err := scanner.Scan(ctx)
			if err != nil {
				log.Printf("Scan error: %v", err)
				continue
			}
			scanner.displayResults(clients)
		}

	}

}
