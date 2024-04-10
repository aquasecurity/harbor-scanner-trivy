package trivy

import (
	"github.com/stretchr/testify/mock"
)

type MockWrapper struct {
	mock.Mock
}

func (w *MockWrapper) GetVersion() (VersionInfo, error) {
	args := w.Called()
	return args.Get(0).(VersionInfo), args.Error(1)
}

func NewMockWrapper() *MockWrapper {
	return &MockWrapper{}
}

func (w *MockWrapper) Scan(imageRef ImageRef, opt ScanOption) (Report, error) {
	args := w.Called(imageRef, opt)
	return args.Get(0).(Report), args.Error(1)
}
