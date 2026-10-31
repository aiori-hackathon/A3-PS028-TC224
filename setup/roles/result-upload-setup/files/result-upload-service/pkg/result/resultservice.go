package result

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type ResultService struct {
	resultBaseDirectory string
	allowedTestNames    []string
}

func NewResultService(resultBaseDirectory string, allowedTestNames []string) *ResultService {
	return &ResultService{
		resultBaseDirectory: resultBaseDirectory,
		allowedTestNames:    allowedTestNames,
	}
}

func (s *ResultService) StoreResult(testName string, resultData []byte) error {
	if !slices.Contains(s.allowedTestNames, testName) {
		return errors.New("unknown test name")
	}

	if !isJSON(resultData) {
		return errors.New("invalid JSON")
	}

	directoryPath := filepath.Join(s.resultBaseDirectory, testName)
	err := os.MkdirAll(directoryPath, 0755)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.json", time.Now().Format(time.RFC3339Nano))
	err = os.WriteFile(filepath.Join(directoryPath, filename), resultData, 0644)
	if err != nil {
		return err
	}

	slog.Info("result retrieved and stored", "testName", testName, "filename", filename)

	return nil
}

func isJSON(bytes []byte) bool {
	var parsedData json.RawMessage
	err := json.Unmarshal(bytes, &parsedData)

	return err == nil
}
