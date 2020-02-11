package mock

import (
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	"github.com/stretchr/testify/mock"
)

type Wrapper struct {
	mock.Mock
}

func NewWrapper() *Wrapper {
	return &Wrapper{}
}

func (w *Wrapper) Run(imageRef string, auth trivy.RegistryAuth, insecureRegistry bool) (trivy.ScanReport, error) {
	args := w.Called(imageRef, auth, insecureRegistry)
	return args.Get(0).(trivy.ScanReport), args.Error(1)
}
