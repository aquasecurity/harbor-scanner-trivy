package v1

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
)

const (
	pathAPIPrefix        = "/api/v1"
	pathScan             = "/scan"
	pathScanReport       = "/scan/{scan_request_id}/report"
	pathVarScanRequestID = "scan_request_id"
)

type requestHandler struct {
	enqueuer  queue.Enqueuer
	dataStore store.DataStore
	api.BaseHandler
}

func NewAPIHandler(enqueuer queue.Enqueuer, dataStore store.DataStore) http.Handler {
	handler := &requestHandler{
		enqueuer:  enqueuer,
		dataStore: dataStore,
	}

	router := mux.NewRouter()
	v1Router := router.PathPrefix(pathAPIPrefix).Subrouter()

	v1Router.Methods(http.MethodPost).Path(pathScan).HandlerFunc(handler.AcceptScanRequest)
	v1Router.Methods(http.MethodGet).Path(pathScanReport).HandlerFunc(handler.GetScanReport)
	return router
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while unmarshalling scan request")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("unmarshalling scan request: %s", err.Error()),
		})
		return
	}

	if validationError := h.ValidateScanRequest(scanRequest); validationError != nil {
		log.Errorf("Error while validating scan request: %s", validationError.Message)
		h.WriteJSONError(res, *validationError)
		return
	}

	scanJob, err := h.enqueuer.Enqueue(scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while enqueuing scan job")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("enqueuing scan job: %s", err.Error()),
		})
		return
	}
	log.Debugf("Enqueued scan job: %v", scanJob)

	scanResponse := harbor.ScanResponse{ID: scanJob.ID}

	h.WriteJSON(res, scanResponse, api.MimeTypeScanResponse, http.StatusAccepted)
}

func (h *requestHandler) ValidateScanRequest(req harbor.ScanRequest) *harbor.Error {
	if req.Registry.URL == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing registry.url",
		}
	}

	_, err := url.ParseRequestURI(req.Registry.URL)
	if err != nil {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "invalid registry.url",
		}
	}

	if req.Artifact.Repository == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.repository",
		}
	}

	if req.Artifact.Digest == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.digest",
		}
	}

	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	detailsKey, _ := vars[pathVarScanRequestID]

	scanJob, err := h.dataStore.GetScanJob(detailsKey)
	if err != nil {
		log.Printf("ERROR: %v\n", err)
		http.Error(res, "Internal Server Error", 500)
		return
	}

	// TODO Check scan job status and inspect Accept header
	h.WriteJSON(res, scanJob.Reports.HarborScanReport, api.MimeTypeHarborVulnerabilityReport, http.StatusOK)
}
