package binary

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	Magic   = "NXFW"
	Version = 1
)

// Record represents a single IP/CIDR record in binary format
type Record struct {
	IP        net.IP
	PrefixLen uint8
	IsIPv6    bool
}

// Encode records to a writer
func Encode(w io.Writer, records []Record) error {
	// Write Magic
	if _, err := w.Write([]byte(Magic)); err != nil {
		return err
	}

	// Write Version
	if _, err := w.Write([]byte{Version}); err != nil {
		return err
	}

	// Reserved 3 bytes
	if _, err := w.Write([]byte{0, 0, 0}); err != nil {
		return err
	}

	var ipv4Records []Record
	var ipv6Records []Record

	for _, r := range records {
		if r.IsIPv6 {
			ipv6Records = append(ipv6Records, r)
		} else {
			ipv4Records = append(ipv4Records, r)
		}
	}

	// Write IPv4 Count
	if err := binary.Write(w, binary.LittleEndian, uint32(len(ipv4Records))); err != nil {
		return err
	}

	// Write IPv6 Count
	if err := binary.Write(w, binary.LittleEndian, uint32(len(ipv6Records))); err != nil {
		return err
	}

	// Write IPv4 Data: [4 bytes IP][1 byte Prefix]
	for _, r := range ipv4Records {
		if _, err := w.Write(r.IP.To4()); err != nil {
			return err
		}
		if _, err := w.Write([]byte{r.PrefixLen}); err != nil {
			return err
		}
	}

	// Write IPv6 Data: [16 bytes IP][1 byte Prefix]
	for _, r := range ipv6Records {
		if _, err := w.Write(r.IP.To16()); err != nil {
			return err
		}
		if _, err := w.Write([]byte{r.PrefixLen}); err != nil {
			return err
		}
	}

	return nil
}

// Decode records from a reader
func Decode(r io.Reader) ([]Record, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	if string(magic) != Magic {
		return nil, fmt.Errorf("invalid magic: %s", string(magic))
	}

	version := make([]byte, 1)
	if _, err := io.ReadFull(r, version); err != nil {
		return nil, err
	}
	if version[0] != Version {
		return nil, fmt.Errorf("unsupported version: %d", version[0])
	}

	// Skip reserved 3 bytes
	reserved := make([]byte, 3)
	if _, err := io.ReadFull(r, reserved); err != nil {
		return nil, err
	}

	var ipv4Count uint32
	if err := binary.Read(r, binary.LittleEndian, &ipv4Count); err != nil {
		return nil, err
	}

	var ipv6Count uint32
	if err := binary.Read(r, binary.LittleEndian, &ipv6Count); err != nil {
		return nil, err
	}

	records := make([]Record, 0, ipv4Count+ipv6Count)

	// Read IPv4 Data
	for i := uint32(0); i < ipv4Count; i++ {
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, err
		}
		prefix := make([]byte, 1)
		if _, err := io.ReadFull(r, prefix); err != nil {
			return nil, err
		}
		records = append(records, Record{
			IP:        net.IP(ip),
			PrefixLen: prefix[0],
			IsIPv6:    false,
		})
	}

	// Read IPv6 Data
	for i := uint32(0); i < ipv6Count; i++ {
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, err
		}
		prefix := make([]byte, 1)
		if _, err := io.ReadFull(r, prefix); err != nil {
			return nil, err
		}
		records = append(records, Record{
			IP:        net.IP(ip),
			PrefixLen: prefix[0],
			IsIPv6:    true,
		})
	}

	return records, nil
}
