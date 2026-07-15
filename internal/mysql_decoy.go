package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"time"

	"log/slog"

	"krain-sec/internal/store"
)

// StartMySQLDecoy listens like MySQL 8.x: real-looking handshake, then denies / tarpits.
// No data, no auth success — scanners see an open 3306.
func StartMySQLDecoy(ctx context.Context) error {
	ln, err := net.Listen("tcp", ":3306")
	if err != nil {
		return fmt.Errorf("mysql decoy listen: %w", err)
	}
	slog.Info("mysql listen", "addr", ":3306")

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Warn("mysql accept failed", "err", err)
				continue
			}
		}
		sem := mysqlDecoySem()
		if !sem.tryAcquire() {
			_ = conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer sem.release()
			handleMySQLDecoy(c)
		}(conn)
	}
}

func handleMySQLDecoy(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	slog.Info("mysql connect", "ip", remote)
	store.RecordDecoy("mysql", stripPort(remote), "connect")
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))

	// Artificial lag before greeting (backend “busy”)
	time.Sleep(time.Duration(800+rand.IntN(2200)) * time.Millisecond)

	greeting := mysqlGreeting()
	if _, err := conn.Write(greeting); err != nil {
		return
	}

	// Read client auth packet (or anything), then deny slowly
	buf := make([]byte, 4096)
	_, _ = conn.Read(buf)

	time.Sleep(time.Duration(1500+rand.IntN(3500)) * time.Millisecond)

	// ERR packet: Access denied for user ...
	errPkt := mysqlErrorPacket(1045, "28000", "Access denied for user 'root'@'"+stripPort(remote)+"' (using password: YES)")
	_, _ = conn.Write(errPkt)

	// Hold the socket a bit so automated tools stall
	time.Sleep(time.Duration(2+rand.IntN(6)) * time.Second)
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, 1024))
}

func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func mysqlGreeting() []byte {
	// Minimal Protocol::HandshakeV10 shaped like MySQL 8.4
	version := append([]byte("8.4.10"), 0x00)
	connID := make([]byte, 4)
	binary.LittleEndian.PutUint32(connID, uint32(rand.IntN(1<<28)+1000))

	authPluginDataPart1 := make([]byte, 8)
	for i := range authPluginDataPart1 {
		authPluginDataPart1[i] = byte(rand.IntN(256))
	}
	filler := byte(0x00)
	capabilityLower := []byte{0xff, 0xff} // lower 16 capability flags
	charset := byte(0xff)                 // utf8mb4
	statusFlags := []byte{0x02, 0x00}
	capabilityUpper := []byte{0xff, 0xc7}
	authPluginDataLen := byte(21)
	reserved := make([]byte, 10)
	authPluginDataPart2 := make([]byte, 12)
	for i := range authPluginDataPart2 {
		authPluginDataPart2[i] = byte(rand.IntN(256))
	}
	authPluginDataPart2 = append(authPluginDataPart2, 0x00)
	plugin := append([]byte("caching_sha2_password"), 0x00)

	payload := []byte{0x0a} // protocol version
	payload = append(payload, version...)
	payload = append(payload, connID...)
	payload = append(payload, authPluginDataPart1...)
	payload = append(payload, filler)
	payload = append(payload, capabilityLower...)
	payload = append(payload, charset)
	payload = append(payload, statusFlags...)
	payload = append(payload, capabilityUpper...)
	payload = append(payload, authPluginDataLen)
	payload = append(payload, reserved...)
	payload = append(payload, authPluginDataPart2...)
	payload = append(payload, plugin...)

	return mysqlPacket(0, payload)
}

func mysqlErrorPacket(code uint16, state, msg string) []byte {
	payload := []byte{0xff}
	c := make([]byte, 2)
	binary.LittleEndian.PutUint16(c, code)
	payload = append(payload, c...)
	payload = append(payload, '#')
	payload = append(payload, []byte(state)...)
	payload = append(payload, []byte(msg)...)
	return mysqlPacket(2, payload)
}

func mysqlPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	hdr := []byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
	return append(hdr, payload...)
}
