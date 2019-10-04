package trivy

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/trivy"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"io/ioutil"
	"os"
	"os/exec"
)

// RegistryAuth wraps registry credentials.
type RegistryAuth struct {
	Username string
	Password string
}

type Wrapper interface {
	Run(imageRef string, auth RegistryAuth) (trivy.ScanResult, error)
}

type wrapper struct {
	config etc.WrapperConfig
}

func NewWrapper(config etc.WrapperConfig) Wrapper {
	return &wrapper{
		config: config,
	}
}

func (w *wrapper) Run(imageRef string, auth RegistryAuth) (report trivy.ScanResult, err error) {
	log.WithField("image_ref", imageRef).Debug("Started scanning")

	executable, err := exec.LookPath("trivy")
	if err != nil {
		return report, err
	}

	reportFile, err := ioutil.TempFile("", "trivy-scan-report-*.json")
	if err != nil {
		return report, err
	}
	log.WithField("path", reportFile.Name()).Debug("Saving scan report to tmp file")
	defer func() {
		log.WithField("path", reportFile.Name()).Debug("Removing scan report tmp file")
		err := os.Remove(reportFile.Name())
		if err != nil {
			log.WithError(err).Warn("Error while removing scan report file")
		}
	}()

	cmd := exec.Command(executable,
		"--quiet",
		"--cache-dir", w.config.TrivyCacheDir,
		"--vuln-type", "os",
		"--format", "json",
		"--output", reportFile.Name(),
		imageRef,
	)

	cmd.Env = os.Environ()
	if auth.Username != "" && auth.Password != "" {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("TRIVY_USERNAME=%s", auth.Username),
			fmt.Sprintf("TRIVY_PASSWORD=%s", auth.Password))
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return report, xerrors.Errorf("running trivy: %v", err)
	}

	log.Debugf("trivy exit code: %d", cmd.ProcessState.ExitCode())
	log.Debugf("Finished scanning %s", imageRef)

	var data []trivy.ScanResult
	err = json.NewDecoder(reportFile).Decode(&data)
	if err != nil {
		return report, xerrors.Errorf("decoding scan report from file %v", err)
	}
	// TODO ASSERT len(data) == 0
	report = data[0]
	return
}
