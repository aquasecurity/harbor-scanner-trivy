package mock

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
	"github.com/stretchr/testify/mock"
)

type Transformer struct {
	mock.Mock
}

func NewTransformer() *Transformer {
	return &Transformer{}
}

func (t *Transformer) Transform(artifact harbor.Artifact, source trivy.ScanReport) harbor.ScanReport {
	args := t.Called(artifact, source)
	return args.Get(0).(harbor.ScanReport)
}
