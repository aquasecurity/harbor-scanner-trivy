package v1

import (
	"encoding/json"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/image"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type APIHandler struct {
	scanner image.Scanner
}

func NewAPIHandler(scanner image.Scanner) *APIHandler {
	return &APIHandler{
		scanner: scanner,
	}
}

func (h *APIHandler) GetVersion(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *APIHandler) CreateScan(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.Printf("ERROR: %v\n", err)
		http.Error(res, "Internal Server Error", 500)
		return
	}

	scanResponse, err := h.scanner.Scan(scanRequest)
	if err != nil {
		log.Printf("ERROR: %v\n", err)
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.WriteHeader(http.StatusCreated)

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResponse)
	if err != nil {
		log.Printf("ERROR: %v\n", err)
		http.Error(res, "Internal Server Error", 500)
		return
	}
}

func (h *APIHandler) GetScanResult(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	detailsKey, _ := vars["detailsKey"]

	scanResult, err := h.scanner.GetResult(detailsKey)
	if err != nil {
		log.Printf("ERROR: %v\n", err)
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResult)
	if err != nil {
		log.Printf("ERROR: %v\n", err)
		http.Error(res, "Internal Server Error", 500)
		return
	}
}
