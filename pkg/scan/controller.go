package scan

import (
	"context"
	"encoding/base64"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"log/slog"
	"strings"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
)

type Controller interface {
	Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error
}

type controller struct {
	store       persistence.Store
	wrapper     trivy.Wrapper
	transformer Transformer
}

func NewController(store persistence.Store, wrapper trivy.Wrapper, transformer Transformer) Controller {
	return &controller{
		store:       store,
		wrapper:     wrapper,
		transformer: transformer,
	}
}

func (c *controller) Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error {
	if err := c.scan(ctx, scanJobKey, request); err != nil {
		slog.Error("Scan failed", slog.String("err", err.Error()))
		if err = c.store.UpdateStatus(ctx, scanJobKey, job.Failed, err.Error()); err != nil {
			return xerrors.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobKey job.ScanJobKey, req *harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	err = c.store.UpdateStatus(ctx, scanJobKey, job.Pending)
	if err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	imageRef, nonSSL, err := req.GetImageRef()
	if err != nil {
		return err
	}

	auth, err := c.ToRegistryAuth(req.Registry.Authorization)
	if err != nil {
		return err
	}

	ref := trivy.ImageRef{
		Name:   imageRef,
		Auth:   auth,
		NonSSL: nonSSL,
	}

	scanReport, err := c.wrapper.Scan(ref, trivy.ScanOption{
		Format: determineFormat(scanJobKey.MediaType),
	})
	if err != nil {
		return xerrors.Errorf("running trivy wrapper: %v", err)
	}

	harborScanReport := c.transformer.Transform(scanJobKey.MediaType, lo.FromPtr(req), scanReport)
	if err = c.store.UpdateReport(ctx, scanJobKey, harborScanReport); err != nil {
		return xerrors.Errorf("saving scan report: %v", err)
	}

	if err = c.store.UpdateStatus(ctx, scanJobKey, job.Finished); err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	return
}

func (c *controller) ToRegistryAuth(authorization string) (auth trivy.RegistryAuth, err error) {
	if authorization == "" {
		return trivy.NoAuth{}, nil
	}

	tokens := strings.Split(authorization, " ")
	if len(tokens) != 2 {
		return auth, xerrors.Errorf("parsing authorization: expected <type> <credentials> got %s", authorization)
	}

	switch tokens[0] {
	case "Basic":
		return c.decodeBasicAuth(tokens[1])
	case "Bearer":
		return trivy.BearerAuth{
			Token: tokens[1],
		}, nil
	}

	return auth, xerrors.Errorf("unrecognized authorization type: %s", tokens[0])
}

func (c *controller) decodeBasicAuth(value string) (auth trivy.RegistryAuth, err error) {
	creds, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return auth, err
	}
	tokens := strings.Split(string(creds), ":")
	auth = trivy.BasicAuth{
		Username: tokens[0],
		Password: tokens[1],
	}
	return
}

func determineFormat(m api.MediaType) trivy.Format {
	switch m {
	case api.MediaTypeSPDX:
		return trivy.FormatSPDX
	case api.MediaTypeCycloneDX:
		return trivy.FormatCycloneDX
	default:
		return trivy.FormatJSON
	}
}
