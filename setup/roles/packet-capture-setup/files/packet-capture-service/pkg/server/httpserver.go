package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"packet-capture-service/pkg/correlation"
)

func NewHTTPServer(address string, correlationService *correlation.CorrelationService) *http.Server {
	mux := http.NewServeMux()

	mux.Handle("/", connectionAttemptTraceHandler(correlationService))

	return &http.Server{
		Addr:    address,
		Handler: mux,
	}
}

func connectionAttemptTraceHandler(correlationService *correlation.CorrelationService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		sni := request.Header.Get("X-SNI")
		if sni == "" {
			http.Error(writer, "X-SNI header is missing", http.StatusBadRequest)
			return
		}

		// allow some time to process the last packet of this connection
		time.Sleep(200 * time.Millisecond)

		slog.Info("connection attempt trace request", "sni", sni)

		correlatingPackets, found := correlationService.GetCorrelatingPacketsForSNI(sni)
		if found {
			// delete the correlation after the request, since it's only queried once
			correlationService.DeleteCorrelation(sni)
		}

		writer.Header().Set("Content-Type", "application/json")

		err := json.NewEncoder(writer).Encode(correlatingPackets)
		if err != nil {
			slog.Error("error encoding response", "error", err)
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	})
}
