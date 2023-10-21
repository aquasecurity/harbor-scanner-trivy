package etc

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// Check checks config values to fail fast in case of any problems
// that we might have due to invalid config.
func Check(config Config) error {
	slog.Debug("Current process", slog.Int("pid", os.Getpid()))

	slog.Debug("Current user",
		slog.Int("uid", os.Getuid()),
		slog.Int("gid", os.Getegid()),
		slog.String("home_dir", os.Getenv("HOME")),
	)

	if config.Trivy.CacheDir == "" {
		return errors.New("trivy cache dir must not be blank")
	}

	if config.Trivy.ReportsDir == "" {
		return errors.New("trivy reports dir must not be blank")
	}

	if err := ensureDirExists(config.Trivy.CacheDir, "trivy cache dir"); err != nil {
		return err
	}

	if err := ensureDirExists(config.Trivy.ReportsDir, "trivy reports dir"); err != nil {
		return err
	}

	if config.API.IsTLSEnabled() {
		if !fileExists(config.API.TLSCertificate) {
			return fmt.Errorf("TLS certificate file does not exist: %s", config.API.TLSCertificate)
		}

		if !fileExists(config.API.TLSKey) {
			return fmt.Errorf("TLS private key file does not exist: %s", config.API.TLSKey)
		}

		for _, path := range config.API.ClientCAs {
			if !fileExists(path) {
				return fmt.Errorf("ClientCA file does not exist: %s", path)
			}
		}
	}

	return nil
}

func ensureDirExists(path, description string) error {
	logger := slog.With(slog.String("path", path))
	if !dirExists(path) {
		logger.Warn(fmt.Sprintf("%s does not exist", description))
		logger.Debug(fmt.Sprintf("Creating %s", description))
		if err := os.MkdirAll(path, 0777); err != nil {
			return fmt.Errorf("creating %s: %w", description, err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}

	logger.Debug(fmt.Sprintf("%s permissions", description), slog.String("mode", fi.Mode().String()))
	return nil
}

// dirExists checks if a dir exists before we
// try using it to prevent further errors.
func dirExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
