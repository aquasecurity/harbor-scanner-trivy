package ext

import (
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/mock"
	"os"
	"os/exec"
)

type MockAmbassador struct {
	mock.Mock
}

func NewMockAmbassador() *MockAmbassador {
	return &MockAmbassador{}
}

func (m *MockAmbassador) Environ() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockAmbassador) LookPath(file string) (string, error) {
	args := m.Called(file)
	return args.String(0), args.Error(1)
}

func (m *MockAmbassador) TempFile(dir, pattern string) (*os.File, error) {
	args := m.Called(dir, pattern)
	return args.Get(0).(*os.File), args.Error(1)
}

func (m *MockAmbassador) RunCmd(cmd *exec.Cmd) ([]byte, error) {
	args := m.Called(cmd)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockAmbassador) RemoteImage(ref name.Reference, options ...remote.Option) (v1.Image, error) {
	args := m.Called(ref, options)
	return args.Get(0).(v1.Image), args.Error(1)
}
