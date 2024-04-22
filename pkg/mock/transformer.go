package mock

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/stretchr/testify/mock"
)

type Transformer struct {
	mock.Mock
}

func NewTransformer() *Transformer {
	return &Transformer{}
}

func (t *Transformer) Transform(mediaType api.MediaType, req harbor.ScanRequest, source trivy.Report) harbor.ScanReport {
	args := t.Called(mediaType, req, source)
	return args.Get(0).(harbor.ScanReport)
}
