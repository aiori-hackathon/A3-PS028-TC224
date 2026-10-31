package netpacket

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func ParsePacketFromTShark(raw string) (Packet, error) {
	var parsedPacket tsharkPacket
	err := json.Unmarshal([]byte(raw), &parsedPacket)
	if err != nil {
		return Packet{}, err
	}

	timestamp, err := parsedPacket.parseTime()
	if err != nil {
		return Packet{}, err
	}

	sourceIP, err := parsedPacket.parseSourceIP()
	if err != nil {
		return Packet{}, err
	}

	port, err := parsedPacket.parseSourcePort()
	if err != nil {
		return Packet{}, err
	}

	return Packet{
		Timestamp:  timestamp,
		SourceIP:   sourceIP,
		SourcePort: port,
		Protocol:   parsedPacket.getProtocol(),
		SNI:        parsedPacket.getSNI(),
	}, nil
}

type tsharkPacket struct {
	Layers layers `json:"layers"`
}

type layers struct {
	TimeEpoch     []string `json:"frame_time_epoch"`
	IPv4Source    []string `json:"ip_src"`
	IPv6Source    []string `json:"ipv6_src"`
	SourceTCPPort []string `json:"tcp_srcport"`
	SourceUDPPort []string `json:"udp_srcport"`
	Protocols     []string `json:"frame_protocols"`
	SNI           []string `json:"tls_handshake_extensions_server_name"`
}

func (p tsharkPacket) parseTime() (time.Time, error) {
	if len(p.Layers.TimeEpoch) == 0 {
		return time.Time{}, errors.New("no timestamp found")
	}

	float, err := strconv.ParseFloat(p.Layers.TimeEpoch[0], 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.UnixMilli(int64(float * 1000)), nil
}

func (p tsharkPacket) parseSourceIP() (netip.Addr, error) {
	if len(p.Layers.IPv4Source) != 0 {
		return netip.ParseAddr(p.Layers.IPv4Source[0])
	}

	if len(p.Layers.IPv6Source) != 0 {
		return netip.ParseAddr(p.Layers.IPv6Source[0])
	}

	return netip.Addr{}, errors.New("no source IP found")
}

func (p tsharkPacket) parseSourcePort() (int, error) {
	if len(p.Layers.SourceTCPPort) != 0 {
		return strconv.Atoi(p.Layers.SourceTCPPort[0])
	}

	if len(p.Layers.SourceUDPPort) != 0 {
		return strconv.Atoi(p.Layers.SourceUDPPort[0])
	}

	return 0, errors.New("no source port found")
}

func (p tsharkPacket) getProtocol() string {
	if len(p.Layers.Protocols) == 0 {
		return ""
	}

	protocols := p.Layers.Protocols[0]

	if strings.HasSuffix(protocols, ":tcp") {
		return "TCP (SYN)"
	}

	if strings.HasSuffix(protocols, ":tcp:tls") {
		return "TLS"
	}

	if strings.HasSuffix(protocols, ":quic:tls") {
		return "QUIC"
	}

	return protocols
}

func (p tsharkPacket) getSNI() string {
	if len(p.Layers.SNI) == 0 {
		return ""
	}

	return p.Layers.SNI[0]
}
