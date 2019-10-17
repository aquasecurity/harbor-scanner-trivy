package scan

import (
	"encoding/base64"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/job"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/store"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"strings"
)

type Controller interface {
	Scan(scanJobID string, request harbor.ScanRequest) error
}

type controller struct {
	dataStore   store.DataStore
	wrapper     trivy.Wrapper
	transformer model.Transformer
}

func NewController(dataStore store.DataStore, wrapper trivy.Wrapper, transformer model.Transformer) Controller {
	return &controller{
		dataStore:   dataStore,
		wrapper:     wrapper,
		transformer: transformer,
	}
}

func (c *controller) Scan(scanJobID string, request harbor.ScanRequest) error {
	err := c.scan(scanJobID, request)
	if err != nil {
		log.WithError(err).Error("Scan failed")
		err = c.dataStore.UpdateStatus(scanJobID, job.Failed, err.Error())
		if err != nil {
			return xerrors.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (c *controller) scan(scanJobID string, req harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	err = c.dataStore.UpdateStatus(scanJobID, job.Pending)
	if err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	imageRef, err := req.GetImageRef()
	if err != nil {
		return err
	}

	auth, err := c.ToRegistryAuth(req.Registry.Authorization)
	if err != nil {
		return err
	}

	scanReport, err := c.wrapper.Run(imageRef, auth)
	if err != nil {
		return xerrors.Errorf("running trivy wrapper: %v", err)
	}

	err = c.dataStore.UpdateReport(scanJobID, c.transformer.Transform(req.Artifact, scanReport))
	if err != nil {
		return xerrors.Errorf("saving scan report: %v", err)
	}

	err = c.dataStore.UpdateStatus(scanJobID, job.Finished)
	if err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	return
}

func (c *controller) ToRegistryAuth(authorization string) (auth trivy.RegistryAuth, err error) {
	tokens := strings.Split(authorization, " ")
	if len(tokens) != 2 {
		return auth, xerrors.Errorf("parsing authorization: expected <type> <credentials> got %s", authorization)
	}
	switch tokens[0] {
	case "Basic":
		return c.decodeBasicAuth(tokens[1])
	}
	return auth, xerrors.Errorf("unrecognized authorization type: %s", tokens[0])
}

func (c *controller) decodeBasicAuth(value string) (auth trivy.RegistryAuth, err error) {
	creds, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return auth, err
	}
	tokens := strings.Split(string(creds), ":")
	auth = trivy.RegistryAuth{
		Username: tokens[0],
		Password: tokens[1],
	}
	return
}
