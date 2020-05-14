package etc

import (
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// Check checks config values to fail fast in case of any problems
// that we might have due to invalid config.
func Check(config Config) (err error) {
	log.WithFields(log.Fields{
		"pid": os.Getpid(),
	}).Debug("Current process")

	log.WithFields(log.Fields{
		"uid":      os.Getuid(),
		"gid":      os.Getegid(),
		"home_dir": os.Getenv("HOME"),
	}).Debug("Current user")

	if config.Trivy.CacheDir == "" {
		err = errors.New("trivy cache dir must not be blank")
		return
	}

	if config.Trivy.ReportsDir == "" {
		err = errors.New("trivy reports dir must not be blank")
		return
	}

	if err = ensureDirExists(config.Trivy.CacheDir, "trivy cache dir"); err != nil {
		return
	}

	if err = ensureDirExists(config.Trivy.ReportsDir, "trivy reports dir"); err != nil {
		return
	}

	if config.API.IsTLSEnabled() {
		if !fileExists(config.API.TLSCertificate) {
			err = fmt.Errorf("TLS certificate file does not exist: %s", config.API.TLSCertificate)
			return
		}

		if !fileExists(config.API.TLSKey) {
			err = fmt.Errorf("TLS private key file does not exist: %s", config.API.TLSKey)
			return
		}

		for _, path := range config.API.ClientCAs {
			if !fileExists(path) {
				err = fmt.Errorf("ClientCA file does not exist: %s", path)
				return
			}
		}
	}

	return
}

func ensureDirExists(path, description string) (err error) {
	if !dirExists(path) {
		log.WithField("path", path).Warnf("%s does not exist", description)
		log.WithField("path", path).Debugf("Creating %s", description)
		if err = os.MkdirAll(path, 0777); err != nil {
			err = fmt.Errorf("creating %s: %w", description, err)
			return
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return
	}

	log.WithFields(log.Fields{
		"mode": fi.Mode().String(),
	}).Debugf("%s permissions", description)
	return
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
