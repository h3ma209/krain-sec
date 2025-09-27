package honeypot

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type Client struct {
	IP          net.IP
	Port        int
	Protocol    string
	ConnectedAt time.Time
	Duration    time.Duration
}

type Service struct {
	Name     string
	Port     int
	listener net.Listener
	clients  []Client
	mutex    sync.Mutex
}

type Honeypot struct {
	services []Service
}

func NewHoneyPot() *Honeypot {
	return &Honeypot{
		services: make([]Service, 0),
	}
}

func (h *Honeypot) AddService(name string, port int) {
	service := Service{
		Name:    name,
		Port:    port,
		clients: make([]Client, 0),
	}
	h.services = append(h.services, service)
}

func (h *Honeypot) StartAllServices(ctx context.Context) error {
	for i := range h.services {
		srv := &h.services[i]
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", srv.Port))
		if err != nil {
			return err
		}
		srv.listener = ln
		fmt.Printf("[+] Listening on port %d\n", srv.Port)

		go h.handleConnections(ctx, srv)
	}
	return nil
}

func (h *Honeypot) handleConnections(ctx context.Context, service *Service) {
	defer service.listener.Close()

	connChan := make(chan net.Conn)
	errChan := make(chan error)

	go func() {
		for {
			conn, err := service.listener.Accept()

			if err != nil {
				errChan <- err
				return
			}
			connChan <- conn
		}
	}()

	for {

		select {
		case <-ctx.Done():
			fmt.Printf("%s Stopped due to intruption", service.Name)
			return
		case conn := <-connChan:
			client := Client{
				IP:          conn.RemoteAddr().(*net.TCPAddr).IP,
				Port:        conn.RemoteAddr().(*net.TCPAddr).Port,
				Protocol:    "TCP",
				ConnectedAt: time.Now(),
			}
			service.mutex.Lock()
			service.clients = append(service.clients, client)
			service.mutex.Unlock()

			fmt.Printf("[+] New connection from %s to service %s on port %d\n", client.IP, service.Name, service.Port)
			go h.handleConnection(ctx, conn)
			h.AnalyzeClientsIntentions()
		case err := <-errChan:
			select {
			case <-ctx.Done():
				return
			default:
				fmt.Printf("%s service error: %v\n", service.Name, err)
				return
			}
		}

	}
}

func (h *Honeypot) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	connCtx, connCancel := context.WithTimeout(ctx, 30*time.Second)

	defer connCancel()

	select {
	case <-connCtx.Done():
		if connCtx.Err() == context.DeadlineExceeded {
			fmt.Printf("Connection from %s timedout\n", conn.RemoteAddr())
		} else {
			fmt.Println("Probably connection canceled")
		}
	case <-time.After(1 * time.Second):
		fmt.Printf("Closing connection from %s\n", conn.RemoteAddr())
	}
}

func (h *Honeypot) StopAllServices() {
	for i := range h.services {
		service := &h.services[i]

		if service.listener != nil {
			fmt.Printf("Stopping Service %s on port %d\n", service.Name, service.Port)
			service.listener.Close()
		}
	}
}

func (h *Honeypot) AnalyzeClientsIntentions() {
	clientsWithServices := make(map[string][]string, 0)
	for i := range h.services {
		service := &h.services[i]
		service.mutex.Lock()
		for _, client := range service.clients {
			ipStr := client.IP.String()
			clientInfo := fmt.Sprintf("serviceName: %s, conTime: %s", service.Name, client.ConnectedAt.Format("2006-01-02 15:04:05"))
			clientsWithServices[ipStr] = append(clientsWithServices[ipStr], clientInfo)
		}
		service.mutex.Unlock()
	}

	for ip, serviceInfo := range clientsWithServices {
		fmt.Printf("Client %s interacted with services: %v\n", ip, serviceInfo)
	}
}
