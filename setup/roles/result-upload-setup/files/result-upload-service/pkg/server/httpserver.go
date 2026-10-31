package server

import (
	"io"
	"log/slog"
	"net/http"

	"result-upload-service/pkg/result"
)

func NewHTTPServer(address string, resultService *result.ResultService) *http.Server {
	mux := http.NewServeMux()

	mux.Handle("POST /results/{testName}", resultUploadHandler(resultService))

	return &http.Server{
		Addr:    address,
		Handler: mux,
	}
}

func resultUploadHandler(resultService *result.ResultService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		testName := request.PathValue("testName")
		if testName == "" {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = resultService.StoreResult(testName, body)
		if err != nil {
			slog.Error("failed to store result", "error", err, "testName", testName)
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		writer.WriteHeader(http.StatusCreated)
	})
}
