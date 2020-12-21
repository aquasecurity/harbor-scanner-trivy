package ext

import (
	"io"
	"os/exec"
	"strings"

	"github.com/stretchr/testify/mock"
)

type FakeFile struct {
	name    string
	content string
	reader  io.Reader
}

// NewFakeFile constructs a new FakeFile with the given name and content.
func NewFakeFile(name, content string) *FakeFile {
	return &FakeFile{
		name:    name,
		content: content,
		reader:  strings.NewReader(content),
	}
}

func (ff *FakeFile) Name() string {
	return ff.name
}

func (ff *FakeFile) Read(p []byte) (int, error) {
	return ff.reader.Read(p)
}

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

func (m *MockAmbassador) RunCmd(cmd *exec.Cmd) ([]byte, error) {
	args := m.Called(cmd)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockAmbassador) TempFile(dir, pattern string) (File, error) {
	args := m.Called(dir, pattern)
	return args.Get(0).(File), args.Error(1)
}

func (m *MockAmbassador) Remove(name string) error {
	args := m.Called(name)
	return args.Error(0)
}
