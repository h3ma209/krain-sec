package main

import (
	"fmt"
	"krain-sec/mitm"
	// "krain-sec/resources"
	"krain-sec/utils"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)


func main() {
	utils.Banner()

	ifaceName := "wlo1"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	fmt.Println("using interface:", iface.Name, iface.HardwareAddr)
	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var ipBase string
	var sourceIP net.IP
	if addr, err := iface.Addrs(); err != nil {
		log.Fatalf("Failed to get addresses for interface %s: %v", ifaceName, err)
	} else {
		for _, a := range addr[:1] {
			if ipNet, ok := a.(*net.IPNet); ok {
				ipParts := strings.Split(ipNet.IP.String(), ".")
				if len(ipParts) == 4 {
					ipBase = fmt.Sprintf("%s.%s.%s.", ipParts[0], ipParts[1], ipParts[2])
				}
				fmt.Println("Using IP base:", ipBase)
				sourceIP = ipNet.IP.To4()
				fmt.Println("Using IP source:", sourceIP)
			}
		}
	}
	timeout := 5 * time.Second

	// go resources.Resources()
	for {
		clientsChan := make(chan []utils.NetworkClient)
		go func() {
			clients := mitm.ScanARP(handle, iface, ipBase, sourceIP, timeout)
			clientsChan <- clients
			close(clientsChan)
		}()
		// go resources.CheckCpu()

		clients := <-clientsChan
		fmt.Println("Discoverd devices: ")
		fmt.Println("| IP Address\t | MAC Address |")
		for _, c := range clients {
			fmt.Printf("IP: %s\t MAC: %s \n", c.IpAddress, c.MacAddress)
		}
	}
}
