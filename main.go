package main

import (
	"fmt"
	"log"
	"net"
	"time"
	"sync"

	// "os"
	// "time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	
)

// create a list for mac adresses that will inserted
type NetworkClient struct {
	MacAddress string
	IpAddress  string
	Hostname   string
	Port       string
	DeviceType string
	DeviceName string
}

// var networkClients []NetworkClient

func main() {
	fmt.Println(`
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓███████▓▒░   ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓███████▓▒░               ░▒▓███████▓▒░ ░▒▓████████▓▒░  ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░        ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░        ░▒▓█▓▒░        ░▒▓█▓▒░        
░▒▓███████▓▒░  ░▒▓███████▓▒░  ░▒▓████████▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░              ░▒▓██████▓▒░  ░▒▓██████▓▒░   ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░                    ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░                    ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░             ░▒▓███████▓▒░  ░▒▓████████▓▒░  ░▒▓██████▓▒░  
	`)
	fmt.Println("WELCOME TO KRIAN - SEC")
	// devices, err := pcap.FindAllDevs()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// for idx, dev := range devices {
	// 	if dev.Addresses != nil && len(dev.Addresses) != 0 {
	// 		fmt.Printf(fmt.Sprintf("[%d] - %s  - %s", idx, dev.Name, dev.Addresses))
	// 	}
	// }
	// CapturePacket()


	ifaceName := "wlo1"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	fmt.Println("using interface:", iface.Name,iface.HardwareAddr)
	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)	
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// packetChan := make(chan gopacket.Packet, 100)
	// var wg sync.WaitGroup

	ipBase := "192.168.1."
	sourceIP := net.ParseIP("192.168.1.19").To4()
	timeout := 10 * time.Second

	clients := scanARP(handle, iface, ipBase, sourceIP, timeout)

	fmt.Println("Discoverd devices: ")
	for _, c := range clients {
		fmt.Printf("IP: %s MAC: %s \n", c.IpAddress, c.MacAddress)
	}
}


func sendARP(handle *pcap.Handle, srcMAC net.HardwareAddr, dstIP, srcIP net.IP) error {
	wl := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}
	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	
	if err := gopacket.SerializeLayers(buf, opts, &wl, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func scanARP(handle *pcap.Handle, iface *net.Interface, ipBase string, srcIP net.IP, timeout time.Duration) []NetworkClient {
	var clients []NetworkClient
	var mu sync.Mutex
	fmt.Println("[!] Pinging For Clients")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	stop := time.After(timeout)

	go func(){
		for packet := range packetSource.Packets(){
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil{
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply{
					client := NetworkClient{
						MacAddress: net.HardwareAddr(arp.SourceHwAddress).String(),
						IpAddress: net.IP(arp.SourceProtAddress).String(),
					}
					mu.Lock()
					clients  = append(clients, client)
					mu.Unlock()
				}
			}

		}
	}()

	var wg sync.WaitGroup
	for i :=1; i <= 254; i++{
		wg.Add(1)
		go func (i int)  {
			defer wg.Done()
			ip:= net.ParseIP(fmt.Sprint("%s%d", ipBase,i))
			_ = sendARP(handle, iface.HardwareAddr, ip, srcIP)
		}(i)
	}
	wg.Wait()
	<-stop
	return clients
}
