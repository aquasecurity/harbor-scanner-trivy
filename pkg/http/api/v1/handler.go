package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	pathVarScanRequestID = "scan_request_id"
)

const (
	propertyScannerType    = "harbor.scanner-adapter/scanner-type"
	propertyDBUpdatedAt    = "harbor.scanner-adapter/vulnerability-database-updated-at"
	propertyDBNextUpdateAt = "harbor.scanner-adapter/vulnerability-database-next-update-at"
)

type requestHandler struct {
	info     etc.BuildInfo
	config   etc.Config
	enqueuer queue.Enqueuer
	store    persistence.Store
	wrapper  trivy.Wrapper
	api.BaseHandler
}

func NewAPIHandler(info etc.BuildInfo, config etc.Config, enqueuer queue.Enqueuer, store persistence.Store, wrapper trivy.Wrapper) http.Handler {
	handler := &requestHandler{
		info:     info,
		config:   config,
		enqueuer: enqueuer,
		store:    store,
		wrapper:  wrapper,
	}

	router := mux.NewRouter()
	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.AcceptScanRequest)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.GetScanReport)
	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.GetMetadata)

	probeRouter := router.PathPrefix("/probe").Subrouter()
	probeRouter.Methods(http.MethodGet).Path("/healthy").HandlerFunc(handler.GetHealthy)
	probeRouter.Methods(http.MethodGet).Path("/ready").HandlerFunc(handler.GetReady)

	router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())

	return router
}

func (h *requestHandler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
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
	var reportMimeType api.MimeType

	err := reportMimeType.FromAcceptHeader(req.Header.Get(api.HeaderAccept))
	if err != nil {
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusUnsupportedMediaType,
			Message:  fmt.Sprintf("unsupported media type %s", req.Header.Get(api.HeaderAccept)),
		})
		return
	}

	vars := mux.Vars(req)
	scanJobID, ok := vars[pathVarScanRequestID]
	if !ok {
		log.Error("Error while parsing `scan_request_id` path variable")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  "missing scan_request_id",
		})
		return
	}

	reqLog := log.WithField("scan_job_id", scanJobID)

	scanJob, err := h.store.Get(scanJobID)
	if err != nil {
		reqLog.Error("Error while getting scan job")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("getting scan job: %v", err),
		})
		return
	}

	if scanJob == nil {
		reqLog.Error("Cannot find scan job")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusNotFound,
			Message:  fmt.Sprintf("cannot find scan job: %v", scanJobID),
		})
		return
	}

	if scanJob.Status == job.Queued || scanJob.Status == job.Pending {
		reqLog.WithField("scan_job_status", scanJob.Status).Debug("Scan job has not finished yet")
		res.Header().Add("Location", req.URL.String())
		res.WriteHeader(http.StatusFound)
		return
	}

	if scanJob.Status == job.Failed {
		reqLog.WithField(log.ErrorKey, scanJob.Error).Error("Scan job failed")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  scanJob.Error,
		})
		return
	}

	if scanJob.Status != job.Finished {
		reqLog.WithField("scan_job_status", scanJob.Status).Error("Unexpected scan job status")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("unexpected status %v of scan job %v", scanJob.Status, scanJob.ID),
		})
		return
	}

	h.WriteJSON(res, scanJob.Report, reportMimeType, http.StatusOK)
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, _ *http.Request) {
	properties := map[string]string{
		propertyScannerType: "os-package-vulnerability",

		"org.label-schema.version":    h.info.Version,
		"org.label-schema.build-date": h.info.Date,
		"org.label-schema.vcs-ref":    h.info.Commit,
		"org.label-schema.vcs":        "https://github.com/aquasecurity/harbor-scanner-trivy",

		"env.SCANNER_TRIVY_SKIP_UPDATE":    strconv.FormatBool(h.config.Trivy.SkipUpdate),
		"env.SCANNER_TRIVY_IGNORE_UNFIXED": strconv.FormatBool(h.config.Trivy.IgnoreUnfixed),
		"env.SCANNER_TRIVY_DEBUG_MODE":     strconv.FormatBool(h.config.Trivy.DebugMode),
		"env.SCANNER_TRIVY_INSECURE":       strconv.FormatBool(h.config.Trivy.Insecure),
		"env.SCANNER_TRIVY_VULN_TYPE":      h.config.Trivy.VulnType,
		"env.SCANNER_TRIVY_SEVERITY":       h.config.Trivy.Severity,
	}

	vi, err := h.wrapper.GetVersion()
	if err != nil {
		log.WithError(err).Error("Error while retrieving vulnerability DB version")
	}

	if err == nil && vi.VulnerabilityDB != nil {
		properties[propertyDBUpdatedAt] = vi.VulnerabilityDB.UpdatedAt.Format(time.RFC3339)
	}

	if err == nil && vi.VulnerabilityDB != nil && !h.config.Trivy.SkipUpdate {
		properties[propertyDBNextUpdateAt] = vi.VulnerabilityDB.NextUpdate.Format(time.RFC3339)
	}

	metadata := &harbor.ScannerAdapterMetadata{
		Scanner: etc.GetScannerMetadata(),
		Capabilities: []harbor.Capability{
			{
				ConsumesMIMETypes: []string{
					api.MimeTypeOCIImageManifest.String(),
					api.MimeTypeDockerImageManifestV2.String(),
				},
				ProducesMIMETypes: []string{
					api.MimeTypeHarborVulnerabilityReport.String(),
					api.MimeTypeSecurityVulnerabilityReport.String(),
				},
			},
		},
		Properties: properties,
	}
	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

func (h *requestHandler) GetHealthy(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) GetReady(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}
