package v1

import (
	"encoding/json"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/image"
	"github.com/aquasecurity/harbor-trivy-adapter/pkg/model/harbor"
	"log"
	"net/http"
	"github.com/gorilla/mux"
)

type APIHandler struct {
	scanner image.Scanner
}

func NewAPIHandler(scanner image.Scanner) *APIHandler {
	return &APIHandler{
		scanner: scanner,
	}
}

func (h *APIHandler) CreateScan(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	log.Printf("CreateScan request received\n\t%v", scanRequest)

	scanResponse, err := h.scanner.Scan(scanRequest)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.WriteHeader(http.StatusCreated)

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResponse)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}
}

func (h *APIHandler) GetScanResult(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	detailsKey, _ := vars["detailsKey"]
	log.Printf("GetScanResult request received (detailsKey=%s)", detailsKey)

	scanResult, err := h.scanner.GetResult(detailsKey)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResult)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}
}
