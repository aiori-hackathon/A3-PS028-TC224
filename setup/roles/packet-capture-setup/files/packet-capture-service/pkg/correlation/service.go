package correlation

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"packet-capture-service/pkg/capture"
	"packet-capture-service/pkg/netpacket"
)

type CorrelationService struct {
	packetCaptureChannel <-chan netpacket.Packet

	uncorrelatedPackets []*netpacket.Packet
	correlationsBySNI   map[string]*packetCorrelation
	mutex               sync.RWMutex
}

func NewCorrelationService(packetCapturePipePath string) (*CorrelationService, error) {
	channel, err := capture.StartReadingFromPacketCapturePipe(packetCapturePipePath)
	if err != nil {
		return nil, err
	}

	s := &CorrelationService{
		packetCaptureChannel: channel,
		uncorrelatedPackets:  make([]*netpacket.Packet, 0, 1000),
		correlationsBySNI:    make(map[string]*packetCorrelation),
	}

	go s.startProcessingCapturedPackets()
	go s.startCleanup()

	return s, nil
}

func (s *CorrelationService) GetCorrelatingPacketsForSNI(sni string) ([]*netpacket.Packet, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	correlation, ok := s.correlationsBySNI[sni]
	if !ok {
		return []*netpacket.Packet{}, false
	}

	return correlation.packets, true
}

func (s *CorrelationService) DeleteCorrelation(sni string) {
	s.mutex.Lock()
	delete(s.correlationsBySNI, sni)
	s.mutex.Unlock()
}

func (s *CorrelationService) startProcessingCapturedPackets() {
	for packet := range s.packetCaptureChannel {
		slog.Info("packet captured", "packet", fmt.Sprintf("%+v", packet))

		s.processPacket(&packet)
	}
}

func (s *CorrelationService) processPacket(packet *netpacket.Packet) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// if the packet has an SNI set, find the corresponding correlation or create it
	if packet.SNI != "" {
		// if there is already a correlation for this SNI, add the packet to it
		// (e.g., a TLS packet with the same SNI as a previous QUIC packet)
		correlation, ok := s.correlationsBySNI[packet.SNI]
		if ok {
			correlation.addPacket(packet)
			s.moveAllUncorrelatedPacketsToCorrelation(correlation)
			return
		}

		// create a new correlation for this SNI
		// (e.g., the first QUIC packet)
		correlation = &packetCorrelation{packets: []*netpacket.Packet{packet}}
		s.moveAllUncorrelatedPacketsToCorrelation(correlation)
		s.correlationsBySNI[packet.SNI] = correlation
		return
	}

	// if there is no SNI set, search all correlations for packets with the same IP address that do correlate
	// (e.g., an IPv6 TCP SYN packet following an IPv6 QUIC packet)
	for _, correlation := range s.correlationsBySNI {
		if correlation.doesPacketCorrelate(packet) {
			correlation.addPacket(packet)
			s.moveAllUncorrelatedPacketsToCorrelation(correlation)
			return
		}
	}

	// if there was no matching correlation and the packet has no SNI, we cannot correlate it yet
	// (e.g., an IPv4 TCP SYN packet)
	s.uncorrelatedPackets = append(s.uncorrelatedPackets, packet)
	return
}

func (s *CorrelationService) moveAllUncorrelatedPacketsToCorrelation(correlation *packetCorrelation) {
	for {
		success := s.moveOneUncorrelatedPacketToCorrelation(correlation)
		if !success {
			break
		}
	}
}

func (s *CorrelationService) moveOneUncorrelatedPacketToCorrelation(correlation *packetCorrelation) bool {
	for i := 0; i < len(s.uncorrelatedPackets); i++ {
		uncorrelatedPacket := s.uncorrelatedPackets[i]

		if correlation.doesPacketCorrelate(uncorrelatedPacket) {
			// add the uncorrelated packet to the correlation
			correlation.addPacket(s.uncorrelatedPackets[i])

			// remove uncorrelated packet from the list of uncorrelated packets
			s.uncorrelatedPackets = append(s.uncorrelatedPackets[:i], s.uncorrelatedPackets[i+1:]...)

			return true
		}
	}

	return false
}

func (s *CorrelationService) startCleanup() {
	for range time.Tick(time.Minute * 10) {
		slog.Info("starting cleanup")

		s.mutex.Lock()

		cutoffTime := time.Now().Add(-time.Minute * 10)

		// remove uncorrelated packets that are older than 10 minutes
		recentUncorrelatedPackets := make([]*netpacket.Packet, 0, len(s.uncorrelatedPackets))
		for _, packet := range s.uncorrelatedPackets {
			if packet.Timestamp.After(cutoffTime) {
				recentUncorrelatedPackets = append(recentUncorrelatedPackets, packet)
			}
		}
		s.uncorrelatedPackets = recentUncorrelatedPackets

		// clean up correlations that are older than 10 minutes
		for sni, correlation := range s.correlationsBySNI {
			if len(correlation.packets) == 0 || correlation.packets[len(correlation.packets)-1].Timestamp.Before(cutoffTime) {
				delete(s.correlationsBySNI, sni)
			}
		}

		s.mutex.Unlock()
		slog.Info("post-cleanup stats", "correlations", len(s.correlationsBySNI), "uncorrelated packets", len(s.uncorrelatedPackets))
	}
}
