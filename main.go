package main

import (
	"context"
	"fmt"
	"krain-sec/honeypot"
	"krain-sec/utils"
	"log"
	"sync"

	// "krain-sec/mitm"
	// "krain-sec/utils"
	// "log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	// "github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

type Config struct {
	InterfaceName string
	Timeout       time.Duration
	IpBase        string
	SourceIP      net.IP
}
type Application struct {
	App *tview.Application
}

// type Scanner struct {
// 	config Config
// 	handle *pcap.Handle
// 	iface  *net.Interface
// }

// func NewScanner(interfaceName string) (*Scanner, error) {
// 	iface, err := net.InterfaceByName(interfaceName)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get Interface %s: %w", interfaceName, err)
// 	}

// 	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)

// 	if err != nil {
// 		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
// 	}

// 	config := Config{
// 		InterfaceName: interfaceName,
// 		Timeout:       5 * time.Second,
// 	}
// 	if err := setIPConfig(&config, iface); err != nil {
// 		handle.Close()
// 		return nil, err
// 	}

// 	return &Scanner{
// 		config: config,
// 		handle: handle,
// 		iface:  iface,
// 	}, nil
// }

// func (s *Scanner) displayResults(clients []utils.NetworkClient) {
// 	fmt.Println("\nDiscovered devices:")
// 	fmt.Println("| IP Address\t\t | MAC Address\t\t |")
// 	fmt.Println("|------------------------|-------------------|")

// 	for _, c := range clients {
// 		fmt.Printf("| %-20s | %-17s |\n", c.IpAddress, c.MacAddress)
// 	}
// 	fmt.Printf("Total devices: %d\n\n", len(clients))
// }
// func setIPConfig(config *Config, iface *net.Interface) error {
// 	addrs, err := iface.Addrs()

// 	if err != nil {
// 		return fmt.Errorf("failed to adddress for the interface %s: %w", config.InterfaceName, err)
// 	}

// 	for _, addr := range addrs {
// 		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
// 			ipv4 := ipNet.IP.To4()
// 			config.SourceIP = ipv4

// 			network := ipNet.IP.Mask(ipNet.Mask)
// 			if netv4 := network.To4(); netv4 != nil {
// 				config.IpBase = fmt.Sprintf("%d.%d.%d", netv4[0], netv4[1], netv4[2])
// 			}
// 			break
// 		}
// 	}

// 	if config.SourceIP == nil {
// 		return fmt.Errorf("no valid ipv4 %s", config.InterfaceName)
// 	}
// 	return nil
// }

// func (s *Scanner) Scan(ctx context.Context) ([]utils.NetworkClient, error) {
// 	return mitm.ScanARP(s.handle, s.iface, s.config.IpBase, s.config.SourceIP, s.config.Timeout)
// }

// func (s *Scanner) Close() {
// 	if s.handle != nil {
// 		s.handle.Close()
// 	}
// }

// func mainTUI() {
// 	application := Application{
// 		App: tview.NewApplication(),
// 	}

// 	// --- Top Section (main container) ---
// 	topSection := tview.NewGrid().
// 		SetRows(0).            // auto expand
// 		SetColumns(60, 1, 40). // left, spacer, right
// 		SetBorders(false)

// 	// --- Left side: Connected Clients list ---
// 	clientsList := tview.NewList().
// 					ShowSecondaryText(false)
// 	clientsList.SetBorder(true).
// 		SetTitle(" Connected Clients ")

// 	//add random macs with device name and ip
// 	clientsList.AddItem("Iphone  - 192.168.1.101 - 00:11:22:33:44:55", "", 0, nil)
// 	clientsList.AddItem("Android - 192.168.1.102 - 00:11:22:33:44:56", "", 0, nil)
// 	clientsList.AddItem("PC      - 192.168.1.103 - 00:11:22:33:44:57", "", 0, nil)

// 	// --- Right side: Device Info ---
// 	deviceInfo := tview.NewTextView().
// 		SetDynamicColors(true).
// 		SetRegions(true).
// 		SetWordWrap(true)
// 	deviceInfo.SetBorder(true).
// 		SetTitle(" Device Info ")

// 	fmt.Fprintf(deviceInfo, "[yellow]Interface:[white] %s\n", "wlo1")
// 	fmt.Fprintf(deviceInfo, "[yellow]IP Base:[white] %s\n", "192.168.1")
// 	fmt.Fprintf(deviceInfo, "[yellow]Source IP:[white] %s\n", "192.168.1.100")

// 	// --- Assemble into top grid ---
// 	topSection.AddItem(clientsList, 0, 0, 1, 1, 0, 0, true)                      // left
// 	topSection.AddItem(tview.NewBox().SetBorder(false), 0, 1, 1, 1, 0, 0, false) // spacer
// 	topSection.AddItem(deviceInfo, 0, 2, 1, 1, 0, 0, true)                       // right

// 	middleSection := tview.NewGrid().
// 		SetRows(0). // auto expand
// 		SetBorders(false)

// 	// set colum names also
// 	middleSectionPacketsTable := tview.NewTable().
// 		SetBorders(true)
// 	middleSectionPacketsTable.SetBorder(true).
// 		SetTitle(" Captured Packets ")

// 	// Set headers
// 	middleSectionPacketsTable.SetCell(0, 0, tview.NewTableCell("No.").SetAlign(tview.AlignCenter).SetSelectable(false))
// 	middleSectionPacketsTable.SetCell(0, 1, tview.NewTableCell("Time").SetAlign(tview.AlignCenter).SetSelectable(false))
// 	middleSectionPacketsTable.SetCell(0, 2, tview.NewTableCell("Source").SetAlign(tview.AlignCenter).SetSelectable(false))
// 	middleSectionPacketsTable.SetCell(0, 3, tview.NewTableCell("Destination").SetAlign(tview.AlignCenter).SetSelectable(false))
// 	middleSectionPacketsTable.SetCell(0, 4, tview.NewTableCell("Protocol").SetAlign(tview.AlignCenter).SetSelectable(false))
// 	middleSectionPacketsTable.SetCell(0, 5, tview.NewTableCell("Length").SetAlign(tview.AlignCenter).SetSelectable(false))
// 	middleSectionPacketsTable.SetCell(0, 6, tview.NewTableCell("Info").SetAlign(tview.AlignCenter).SetSelectable(false))

// 	utils.SetNewNetworkPacketTableCell(middleSectionPacketsTable, 1, 1, "12:00:01", "192.168.1.100", "192.168.1.1", "TCP", "60", "Some info")

// 	middleSection.AddItem(middleSectionPacketsTable, 0, 0, 1, 1, 0, 0, true)

// 	// run
// 	flex := tview.NewFlex().SetDirection(tview.FlexRow).
// 		AddItem(topSection, 0, 1, true).    // top section
// 		AddItem(middleSection, 0, 2, false) // middle section

// 	if err := application.App.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
// 		panic(err)
// 	}
// }

// func scannerMain() {
// 	utils.Banner()
// 	scanner, err := NewScanner("wlo1")

// 	if err != nil {
// 		log.Fatalf("Failed to create Scanner %s", err)
// 	}

// 	defer scanner.Close()
// 	fmt.Printf("Using interface: %s (%s)\n", scanner.iface.Name, scanner.iface.HardwareAddr)
// 	fmt.Printf("Using IP base: %s\n", scanner.config.IpBase)
// 	fmt.Printf("Using IP source: %s\n", scanner.config.SourceIP)

// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	sigChan := make(chan os.Signal, 1)
// 	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

// 	go func() {
// 		<-sigChan
// 		fmt.Println("\n Received Interrupt signal shutting down")
// 		cancel()
// 	}()

// 	ticker := time.NewTicker(10 * time.Second)
// 	defer ticker.Stop()

// 	if clients, err := scanner.Scan(ctx); err != nil {
// 		log.Printf("Scan Error : %v", err)
// 	} else {
// 		scanner.displayResults(clients)
// 	}

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			fmt.Println("Scanner Stopped")
// 			return
// 		case <-ticker.C:
// 			clients, err := scanner.Scan(ctx)
// 			if err != nil {
// 				log.Printf("Scan error: %v", err)
// 				continue
// 			}
// 			scanner.displayResults(clients)
// 		}

// 	}

// }

func main() {

	if err := utils.InitCSV(); err != nil {
		log.Fatalf("Failed to initialize CSV: %v", err)
	}
	defer utils.CloseCSV()
	
	utils.Banner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// make wait group
	var wg sync.WaitGroup

	wg.Add(1)
	go runHoneypot(ctx, &wg)

	<-sigChan
	fmt.Println("\n[!] Received Interrupt signal, shutting down...")
	cancel()

	wg.Wait()
	fmt.Println("All services stopped")
}

func runHoneypot(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	honeypot := honeypot.NewHoneyPot()
	// ctx, cancel := context.WithCancel(context.Background())

	// sigChan := make(chan os.Signal, 1)
	// signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	honeypot.AddService("HTTP", 8080)
	honeypot.AddService("SSH", 2222)

	if err := honeypot.StartAllServices(ctx); err != nil {
		panic(err)
	}
	fmt.Println("[+] Honeypot running Press Ctrl-C to stop")

	<-ctx.Done()
	// time.Sleep(2 * time.Second)

	honeypot.StopAllServices()
	fmt.Println("HoneyPot services stopped gracefully")
}
