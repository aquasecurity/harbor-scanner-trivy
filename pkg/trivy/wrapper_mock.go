package trivy

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/mock"
)

type MockWrapper struct {
	mock.Mock
}

func (w *MockWrapper) GetVersion() (types.VersionInfo, error) {
	panic("implement me!")
}

func NewMockWrapper() *MockWrapper {
	return &MockWrapper{}
}

func (w *MockWrapper) Scan(imageRef ImageRef) (ScanReport, error) {
	args := w.Called(imageRef)
	return args.Get(0).(ScanReport), args.Error(1)
}
