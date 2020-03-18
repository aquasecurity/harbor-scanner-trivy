package ext

import (
	"io/ioutil"
	"os"
	"os/exec"
)

var (
	DefaultAmbassador = &ambassador{}
)

// File abstracts the few methods we need, so we can test without real files.
type File interface {
	Name() string
	Read([]byte) (int, error)
}

// Ambassador the ambassador to the outside "world". Wraps methods that modify global state and hence make the code that
// use them very hard to test.
type Ambassador interface {
	Environ() []string
	LookPath(string) (string, error)
	RunCmd(cmd *exec.Cmd) ([]byte, error)
	TempFile(dir, pattern string) (File, error)
	Remove(name string) error
}

type ambassador struct {
}

func (a *ambassador) Environ() []string {
	return os.Environ()
}

func (a *ambassador) RunCmd(cmd *exec.Cmd) ([]byte, error) {
	return cmd.CombinedOutput()
}

func (a *ambassador) TempFile(dir, pattern string) (File, error) {
	return ioutil.TempFile(dir, pattern)
}

func (a *ambassador) Remove(name string) error {
	return os.Remove(name)
}

func (a *ambassador) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}
