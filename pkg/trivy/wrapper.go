package trivy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	ttypes "github.com/aquasecurity/trivy/pkg/types"
)

const (
	trivyCmd = "trivy"
)

type ImageRef struct {
	Name     string
	Auth     RegistryAuth
	Insecure bool
}

// RegistryAuth wraps registry credentials.
type RegistryAuth struct {
	Username string
	Password string
}

type Wrapper interface {
	Scan(imageRef ImageRef) (ScanReport, error)
	GetVersion() (ttypes.VersionInfo, error)
}

type wrapper struct {
	config     etc.Trivy
	ambassador ext.Ambassador
}

func NewWrapper(config etc.Trivy, ambassador ext.Ambassador) Wrapper {
	return &wrapper{
		config:     config,
		ambassador: ambassador,
	}
}

func (w *wrapper) Scan(imageRef ImageRef) (report ScanReport, err error) {
	log.WithField("image_ref", imageRef.Name).Debug("Started scanning")

	reportFile, err := w.ambassador.TempFile(w.config.ReportsDir, "scan_report_*.json")
	if err != nil {
		return
	}
	log.WithField("path", reportFile.Name()).Debug("Saving scan report to tmp file")
	defer func() {
		log.WithField("path", reportFile.Name()).Debug("Removing scan report tmp file")
		err := w.ambassador.Remove(reportFile.Name())
		if err != nil {
			log.WithError(err).Warn("Error while removing scan report tmp file")
		}
	}()

	cmd, err := w.prepareScanCmd(imageRef, reportFile.Name())
	if err != nil {
		return
	}

	log.WithFields(log.Fields{"path": cmd.Path, "args": cmd.Args}).Trace("Exec command with args")

	stdout, err := w.ambassador.RunCmd(cmd)
	if err != nil {
		log.WithFields(log.Fields{
			"image_ref": imageRef.Name,
			"exit_code": cmd.ProcessState.ExitCode(),
			"std_out":   string(stdout),
		}).Error("Running trivy failed")
		return report, xerrors.Errorf("running trivy: %v: %v", err, string(stdout))
	}

	log.WithFields(log.Fields{
		"image_ref": imageRef.Name,
		"exit_code": cmd.ProcessState.ExitCode(),
		"std_out":   string(stdout),
	}).Debug("Running trivy finished")

	report, err = ScanReportFrom(reportFile)
	return
}

func (w *wrapper) prepareScanCmd(imageRef ImageRef, outputFile string) (*exec.Cmd, error) {
	args := []string{
		"--no-progress",
		"--cache-dir", w.config.CacheDir,
		"--severity", w.config.Severity,
		"--vuln-type", w.config.VulnType,
		"--format", "json",
		"--output", outputFile,
		imageRef.Name,
	}

	if w.config.IgnoreUnfixed {
		args = append([]string{"--ignore-unfixed"}, args...)
	}

	if w.config.DebugMode {
		args = append([]string{"--debug"}, args...)
	}

	if w.config.SkipUpdate {
		args = append([]string{"--skip-update"}, args...)
	}

	name, err := w.ambassador.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)

	cmd.Env = w.ambassador.Environ()
	if imageRef.Auth.Username != "" && imageRef.Auth.Password != "" {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("TRIVY_USERNAME=%s", imageRef.Auth.Username),
			fmt.Sprintf("TRIVY_PASSWORD=%s", imageRef.Auth.Password))
	}
	if imageRef.Insecure {
		cmd.Env = append(cmd.Env, "TRIVY_NON_SSL=true")
	}

	if strings.TrimSpace(w.config.GitHubToken) != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GITHUB_TOKEN=%s", w.config.GitHubToken))
	}
	return cmd, nil
}

func (w *wrapper) GetVersion() (ttypes.VersionInfo, error) {
	versionFile, err := w.ambassador.TempFile(w.config.ReportsDir, "version_*.json")
	if err != nil {
		return ttypes.VersionInfo{}, err
	}
	log.WithField("path", versionFile.Name()).Debug("Saving version output to tmp file")
	defer func() {
		log.WithField("path", versionFile.Name()).Debug("Removing version output tmp file")
		err := w.ambassador.Remove(versionFile.Name())
		if err != nil {
			log.WithError(err).Warn("Error while removing version output tmp file")
		}
	}()

	cmd, err := w.prepareVersionCmd(versionFile.Name())
	if err != nil {
		return ttypes.VersionInfo{}, err
	}

	stdout, err := w.ambassador.RunCmd(cmd)
	if err != nil {
		log.WithFields(log.Fields{
			"exit_code": cmd.ProcessState.ExitCode(),
			"std_out":   string(stdout),
		}).Error("Running trivy failed")
		return ttypes.VersionInfo{}, xerrors.Errorf("running trivy: %v: %v", err, string(stdout))
	}

	b, _ := ioutil.ReadAll(versionFile)
	var vi ttypes.VersionInfo
	_ = json.Unmarshal(b, &vi)

	return vi, nil
}

func (w *wrapper) prepareVersionCmd(outputFile string) (*exec.Cmd, error) {
	args := []string{
		"--version",
		"--cache-dir", w.config.CacheDir,
		"--format", "json",
		"--output", outputFile,
	}

	name, err := w.ambassador.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	return cmd, nil
}
