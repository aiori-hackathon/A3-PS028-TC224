package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"packet-capture-service/pkg/correlation"
	"packet-capture-service/pkg/server"
)

func main() {
	slog.Info("service started")

	err := run()
	if err != nil {
		slog.Error("service failed due to an error", "error", err)
	}

	slog.Info("service stopped")
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	packetCapturePipePath := os.Getenv("PACKET_CAPTURE_PIPE_PATH")
	if packetCapturePipePath == "" {
		return errors.New("PACKET_CAPTURE_PIPE_PATH environment variable is not set")
	}

	correlationService, err := correlation.NewCorrelationService(packetCapturePipePath)
	if err != nil {
		return fmt.Errorf("error starting correlation service: %w", err)
	}

	httpServer := server.NewHTTPServer(":8080", correlationService)

	go func() {
		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server stopped due to an error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("received interrupt signal")

	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	err = httpServer.Shutdown(shutdownContext)
	if err != nil {
		return fmt.Errorf("error shutting down http server: %w", err)
	}

	return nil
}
