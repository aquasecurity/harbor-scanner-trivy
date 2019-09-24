package v1

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/image"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
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
	scanner  image.Scanner
	enqueuer queue.Enqueuer
	api.BaseHandler
}

func NewAPIHandler(scanner image.Scanner, enqueuer queue.Enqueuer) http.Handler {
	handler := &requestHandler{
		scanner:  scanner,
		enqueuer: enqueuer,
	}

	router := mux.NewRouter()
	v1Router := router.PathPrefix(pathAPIPrefix).Subrouter()

	v1Router.Methods(http.MethodPost).Path(pathScan).HandlerFunc(handler.AcceptScanRequest)
	v1Router.Methods(http.MethodGet).Path(pathScanReport).HandlerFunc(handler.GetScanResult)
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

	// TODO This call should go away. I keep it for now so on master we have fully functional adapter.
	scanResponse, err := h.scanner.Scan(scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while scanning")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("scanning: %s", err.Error()),
		})
		return
	}

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

func (h *requestHandler) GetScanResult(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	detailsKey, _ := vars[pathVarScanRequestID]

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
