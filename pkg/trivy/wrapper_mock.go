package trivy

import (
	"github.com/stretchr/testify/mock"
)

type MockWrapper struct {
	mock.Mock
}

func NewMockWrapper() *MockWrapper {
	return &MockWrapper{}
}

func (w *MockWrapper) Scan(imageRef ImageRef) (ScanReport, error) {
	args := w.Called(imageRef)
	return args.Get(0).(ScanReport), args.Error(1)
}
