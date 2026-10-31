package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"result-upload-service/pkg/result"
	"result-upload-service/pkg/server"
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

	resultBaseDirectory := os.Getenv("RESULT_BASE_DIRECTORY")
	if resultBaseDirectory == "" {
		return errors.New("RESULT_BASE_DIRECTORY environment variable is not set")
	}

	allowedTestNames := os.Getenv("ALLOWED_TEST_NAMES")
	if allowedTestNames == "" {
		return errors.New("ALLOWED_TEST_NAMES environment variable is not set")
	}

	resultService := result.NewResultService(resultBaseDirectory, strings.Split(allowedTestNames, ","))

	httpServer := server.NewHTTPServer(":8080", resultService)

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

	err := httpServer.Shutdown(shutdownContext)
	if err != nil {
		return fmt.Errorf("error shutting down http server: %w", err)
	}

	return nil
}
