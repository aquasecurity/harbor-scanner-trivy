package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
)

type Format string

const (
	trivyCmd = "trivy"

	FormatJSON      Format = "json"
	FormatSPDX      Format = "spdx-json"
	FormatCycloneDX Format = "cyclonedx"
)

type ImageRef struct {
	Name   string
	Auth   RegistryAuth
	NonSSL bool
}

type ScanOption struct {
	Format Format
}

// RegistryAuth wraps registry credentials.
type RegistryAuth interface {
}

type NoAuth struct {
}

type BasicAuth struct {
	Username string
	Password string
}

type BearerAuth struct {
	Token string
}

type Wrapper interface {
	Scan(imageRef ImageRef, opt ScanOption) (Report, error)
	GetVersion() (VersionInfo, error)
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

func (w *wrapper) Scan(imageRef ImageRef, opt ScanOption) (Report, error) {
	logger := slog.With(slog.String("image_ref", imageRef.Name))
	logger.Debug("Started scanning")

	target, err := newTarget(imageRef, w.config)
	if err != nil {
		return Report{}, xerrors.Errorf("creating scan target: %w", err)
	}

	reportFile, err := w.ambassador.TempFile(w.config.ReportsDir, "scan_report_*.json")
	if err != nil {
		return Report{}, err
	}
	logger.Debug("Saving scan report to tmp file", slog.String("path", reportFile.Name()))
	defer func() {
		logger.Debug("Removing scan report tmp file", slog.String("path", reportFile.Name()))
		if err = w.ambassador.Remove(reportFile.Name()); err != nil {
			logger.Warn("Error while removing scan report tmp file", slog.String("err", err.Error()))
		}
	}()

	cmd, err := w.prepareScanCmd(target, reportFile.Name(), opt)
	if err != nil {
		return Report{}, err
	}

	logger.Debug("Exec command with args", slog.String("path", cmd.Path),
		slog.String("args", strings.Join(cmd.Args, " ")))

	stdout, err := w.ambassador.RunCmd(cmd)
	if err != nil {
		logger.Error("Running trivy failed",
			slog.String("exit_code", fmt.Sprintf("%d", cmd.ProcessState.ExitCode())),
			slog.String("std_out", string(stdout)),
		)
		return Report{}, fmt.Errorf("running trivy: %v: %v", err, string(stdout))
	}

	logger.Debug("Running trivy finished",
		slog.String("exit_code", fmt.Sprintf("%d", cmd.ProcessState.ExitCode())),
		slog.String("std_out", string(stdout)),
	)

	return w.parseReport(opt.Format, reportFile)
}

func (w *wrapper) parseReport(format Format, reportFile io.Reader) (Report, error) {
	switch format {
	case FormatJSON:
		return w.parseJSONReport(reportFile)
	case FormatSPDX, FormatCycloneDX:
		return w.parseSBOM(reportFile)
	}
	return Report{}, fmt.Errorf("unsupported format %s", format)
}

func (w *wrapper) parseJSONReport(reportFile io.Reader) (Report, error) {
	var scanReport ScanReport
	if err := json.NewDecoder(reportFile).Decode(&scanReport); err != nil {
		return Report{}, xerrors.Errorf("report json decode error: %w", err)
	}

	if scanReport.SchemaVersion != SchemaVersion {
		return Report{}, xerrors.Errorf("unsupported schema %d, expected %d", scanReport.SchemaVersion, SchemaVersion)
	}

	var vulnerabilities []Vulnerability
	for _, scanResult := range scanReport.Results {
		slog.Debug("Parsing vulnerabilities", slog.String("target", scanResult.Target))
		vulnerabilities = append(vulnerabilities, scanResult.Vulnerabilities...)
	}

	return Report{
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (w *wrapper) parseSBOM(reportFile io.Reader) (Report, error) {
	var doc any
	if err := json.NewDecoder(reportFile).Decode(&doc); err != nil {
		return Report{}, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return Report{SBOM: doc}, nil
}

func (w *wrapper) prepareScanCmd(target ScanTarget, outputFile string, opt ScanOption) (*exec.Cmd, error) {
	args := []string{
		string(target.Type), // subcommand
		"--no-progress",
		"--severity", w.config.Severity,
		"--vuln-type", w.config.VulnType,
		"--format", string(opt.Format),
		"--output", outputFile,
		"--cache-dir", w.config.CacheDir,
		"--timeout", w.config.Timeout.String(),
	}

	if target.Type == TargetImage {
		args = append(args, "--scanners", w.config.SecurityChecks)
	}

	if w.config.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	if w.config.SkipUpdate {
		args = append(args, "--skip-db-update")
	}

	if w.config.SkipJavaDBUpdate {
		args = append([]string{"--skip-java-db-update"}, args...)
	}

	if w.config.OfflineScan {
		args = append(args, "--offline-scan")
	}

	if w.config.IgnorePolicy != "" {
		args = append(args, "--ignore-policy")
	}

	if w.config.DebugMode {
		args = append(args, "--debug")
	}

	if w.config.Insecure || target.NonSSL() {
		args = append(args, "--insecure")
	}

	targetName, err := target.Name()
	if err != nil {
		return nil, xerrors.Errorf("get target name: %w", err)
	}
	args = append(args, targetName)

	name, err := w.ambassador.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)

	cmd.Env = w.ambassador.Environ()

	switch a := target.Auth().(type) {
	case NoAuth:
	case BasicAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("TRIVY_USERNAME=%s", a.Username),
			fmt.Sprintf("TRIVY_PASSWORD=%s", a.Password))
	case BearerAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("TRIVY_REGISTRY_TOKEN=%s", a.Token))
	default:
		return nil, fmt.Errorf("invalid auth type %T", a)
	}

	if strings.TrimSpace(w.config.GitHubToken) != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GITHUB_TOKEN=%s", w.config.GitHubToken))
	}

	return cmd, nil
}

func (w *wrapper) GetVersion() (VersionInfo, error) {
	cmd, err := w.prepareVersionCmd()
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed preparing trivy version command: %w", err)
	}

	versionOutput, err := w.ambassador.RunCmd(cmd)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed running trivy version command: %w: %v", err, string(versionOutput))
	}

	var vi VersionInfo
	err = json.Unmarshal(versionOutput, &vi)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed parsing trivy version output: %w", err)
	}

	return vi, nil
}

func (w *wrapper) prepareVersionCmd() (*exec.Cmd, error) {
	args := []string{
		"--cache-dir", w.config.CacheDir,
		"version",
		"--format", "json",
	}

	name, err := w.ambassador.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	return cmd, nil
}
