package mock

import (
	model "github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/stretchr/testify/mock"
)

type Wrapper struct {
	mock.Mock
}

func NewWrapper() *Wrapper {
	return &Wrapper{}
}

func (w *Wrapper) Run(imageRef string, auth trivy.RegistryAuth) (model.ScanReport, error) {
	args := w.Called(imageRef, auth)
	return args.Get(0).(model.ScanReport), args.Error(1)
}
