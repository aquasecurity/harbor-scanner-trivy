package scan

import (
	"context"
	"encoding/base64"
	"log/slog"
	"strings"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"golang.org/x/xerrors"
)

type Controller interface {
	Scan(ctx context.Context, scanJobID string, request harbor.ScanRequest) error
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

func (c *controller) Scan(ctx context.Context, scanJobID string, request harbor.ScanRequest) error {
	if err := c.scan(ctx, scanJobID, request); err != nil {
		slog.Error("Scan failed", slog.String("err", err.Error()))
		if err = c.store.UpdateStatus(ctx, scanJobID, job.Failed, err.Error()); err != nil {
			return xerrors.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobID string, req harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	err = c.store.UpdateStatus(ctx, scanJobID, job.Pending)
	if err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	imageRef, insecureRegistry, err := req.GetImageRef()
	if err != nil {
		return err
	}

	auth, err := c.ToRegistryAuth(req.Registry.Authorization)
	if err != nil {
		return err
	}

	scanReport, err := c.wrapper.Scan(trivy.ImageRef{Name: imageRef, Auth: auth, Insecure: insecureRegistry})
	if err != nil {
		return xerrors.Errorf("running trivy wrapper: %v", err)
	}

	if err = c.store.UpdateReport(ctx, scanJobID, c.transformer.Transform(req.Artifact, scanReport)); err != nil {
		return xerrors.Errorf("saving scan report: %v", err)
	}

	if err = c.store.UpdateStatus(ctx, scanJobID, job.Finished); err != nil {
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
