package ext

import (
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"os"
	"os/exec"
)

var (
	DefaultAmbassador = &ambassador{}
)

// Ambassador the ambassador to the outside "world". Wraps methods that modify global state and hence make the code that
// use them very hard to test.
type Ambassador interface {
	Environ() []string
	LookPath(string) (string, error)
	TempFile(string, string) (*os.File, error)
	RunCmd(cmd *exec.Cmd) ([]byte, error)
	RemoteImage(name.Reference, ...remote.Option) (v1.Image, error)
}

type ambassador struct {
}

func (a *ambassador) Environ() []string {
	return os.Environ()
}

func (a *ambassador) RunCmd(cmd *exec.Cmd) ([]byte, error) {
	return cmd.CombinedOutput()
}

func (a *ambassador) TempFile(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}

func (a *ambassador) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (a *ambassador) RemoteImage(ref name.Reference, options ...remote.Option) (v1.Image, error) {
	return remote.Image(ref, options...)
}
