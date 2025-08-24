package utils

import (
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

type NetworkClient struct {
	MacAddress string
	IpAddress  string
	Hostname   string
	Port       string
	DeviceType string
	DeviceName string
}

type Config struct {
	InterfaceName string
	Timeout       time.Duration
	IpBase        string
	SourceIP      net.IP
}

type Scanner struct {
	config 	Config
	handle *pcap.Handle
	iface  *net.Interface
}
