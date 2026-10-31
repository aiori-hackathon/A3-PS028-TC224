package capture

import (
	"bufio"
	"log/slog"
	"os"
	"strings"

	"packet-capture-service/pkg/netpacket"
)

func StartReadingFromPacketCapturePipe(pipePath string) (<-chan netpacket.Packet, error) {
	channel := make(chan netpacket.Packet, 10000)

	go func() {
		for {
			file, err := os.Open(pipePath)
			if err != nil {
				slog.Error("failed to open pipe", "error", err)
				return
			}

			slog.Info("Listening on pipe...")

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()

				if strings.HasPrefix(line, `{"index"`) {
					continue
				}

				packet, err := netpacket.ParsePacketFromTShark(line)
				if err != nil {
					slog.Error("Failed to parse packet from tshark", "error", err, "line", line)
					continue
				}

				channel <- packet
			}

			err = scanner.Err()
			if err != nil {
				slog.Error("Error reading from pipe", "error", err)
			}

			file.Close()
			slog.Info("tshark disconnected")
		}
	}()

	return channel, nil
}
