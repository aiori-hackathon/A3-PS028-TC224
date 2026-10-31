package correlation

import (
	"net/netip"
	"packet-capture-service/pkg/netpacket"
	"slices"
)

type packetCorrelation struct {
	packets []*netpacket.Packet
}

func (c *packetCorrelation) addPacket(packet *netpacket.Packet) {
	c.packets = append(c.packets, packet)

	slices.SortFunc(c.packets, func(a, b *netpacket.Packet) int {
		return a.Timestamp.Compare(b.Timestamp)
	})
}

func (c *packetCorrelation) doesPacketCorrelate(packetWithoutSNI *netpacket.Packet) bool {
	// if there is a packet with a SNI with the same (source ip, source port), this packet likely corresponds to that connection
	if c.doesContainPacketWithSourceIPAndPort(packetWithoutSNI.SourceIP, packetWithoutSNI.SourcePort) {
		return true
	}

	// if there is no packet with the same (source ip, source port), but the source IP correlates and the timestamp is
	// between two packets in the correlation, the packet likely correlates as well
	if c.doesContainPacketWithSourceIP(packetWithoutSNI) && c.isTimestampInCorrelationTimeFrame(packetWithoutSNI) {
		return true
	}

	return false
}

func (c *packetCorrelation) doesContainPacketWithSourceIPAndPort(sourceIP netip.Addr, port int) bool {
	for _, correlatedPacket := range c.packets {
		if correlatedPacket.SourceIP.Compare(sourceIP) == 0 && correlatedPacket.SourcePort == port {
			return true
		}
	}

	return false
}

func (c *packetCorrelation) doesContainPacketWithSourceIP(packetWithoutSNI *netpacket.Packet) bool {
	for _, correlatedPacket := range c.packets {
		if correlatedPacket.SourceIP.Compare(packetWithoutSNI.SourceIP) == 0 {
			return true
		}
	}

	return false
}

func (c *packetCorrelation) isTimestampInCorrelationTimeFrame(packetWithoutSNI *netpacket.Packet) bool {
	if len(c.packets) < 2 {
		return false
	}

	return c.packets[0].Timestamp.Before(packetWithoutSNI.Timestamp) && c.packets[len(c.packets)-1].Timestamp.After(packetWithoutSNI.Timestamp)
}
