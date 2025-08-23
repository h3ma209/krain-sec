package mitm

import (
	"fmt"
	// "log"
	"net"
	"sync"
	"time"

	// "os"
	// "time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"krain-sec/utils"
)

func SendARP(handle *pcap.Handle, srcMAC net.HardwareAddr, dstIP, srcIP net.IP) error {
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

func ScanARP(handle *pcap.Handle, iface *net.Interface, ipBase string, srcIP net.IP, timeout time.Duration) []utils.NetworkClient {
	var clients []utils.NetworkClient
	var mu sync.Mutex
	fmt.Println("[!] Pinging For Clients")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	stop := time.After(timeout)

	seen := make(map[string]bool) // outside goroutine

	go func() {
		for packet := range packetSource.Packets() {
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply && net.IP(arp.DstProtAddress).Equal(srcIP) {
					ip := net.IP(arp.SourceProtAddress).String()
					mac := net.HardwareAddr(arp.SourceHwAddress).String()

					mu.Lock()
					if !seen[ip] {
						seen[ip] = true
						clients = append(clients, utils.NetworkClient{
							MacAddress: mac,
							IpAddress:  ip,
						})
						// fmt.Printf("IP: %s MAC: %s \n", ip, mac)
					}
					mu.Unlock()
				}
			}
		}
	}()

	jobs := make(chan string, 254)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for ipStr := range jobs {
			ip := net.ParseIP(ipStr)
			_ = SendARP(handle, iface.HardwareAddr, ip, srcIP)
		}
	}
	workerCount := 50
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	for i := 1; i <= 254; i++ {
		jobs <- fmt.Sprintf("%s%d", ipBase, i)

	}
	close(jobs)
	wg.Wait()

	<-stop
	checkForMitmAttack(clients)
	return clients
}

func checkForMitmAttack(clients []utils.NetworkClient) {
	possible_poisned := []utils.NetworkClient{}
	// check for same mac address with different ip addresses
	for i := 0; i < len(clients); i++ {
		for j := i + 1; j < len(clients); j++ {
			if clients[i].MacAddress == clients[j].MacAddress {
				possible_poisned = append(possible_poisned, clients[i])
				break
			}
		}
	}
	if len(possible_poisned) > 0 {
		fmt.Println("[!] Possible MITM attack detected:")
		for _, client := range possible_poisned {
			fmt.Printf("IP: %s MAC: %s \n", client.IpAddress, client.MacAddress)
		}
	} else {
		fmt.Println("[*] No MITM attack detected.")
	}
}
