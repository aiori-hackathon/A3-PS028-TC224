package netpacket

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"time"
)

type Packet struct {
	Timestamp  time.Time
	SourceIP   netip.Addr
	SourcePort int
	Protocol   string
	SNI        string
}

func (p *Packet) MarshalJSON() ([]byte, error) {
	ipVersion := "IPv4"
	if p.SourceIP.Is6() {
		ipVersion = "IPv6"
	}

	protocol := p.Protocol
	if protocol == "TCP" {
		protocol = "TCP (SYN)"
	}

	return json.Marshal(&struct {
		Timestamp     int64  `json:"timestamp"`
		IPVersion     string `json:"ipVersion"`
		Protocol      string `json:"protocol"`
		SourceAddress string `json:"sourceAddress"`
		SourcePort    int    `json:"sourcePort"`
	}{
		Timestamp:     p.Timestamp.UnixMilli(),
		IPVersion:     ipVersion,
		Protocol:      protocol,
		SourceAddress: net.JoinHostPort(p.SourceIP.String(), strconv.Itoa(p.SourcePort)),
		SourcePort:    p.SourcePort,
	})
}

var _ json.Marshaler = (*Packet)(nil)
