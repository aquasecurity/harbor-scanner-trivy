package etc

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {

	t.Run("Should return error when trivy cache dir is blank", func(t *testing.T) {
		tempDir := t.TempDir()
		reportsDir := path.Join(tempDir, "reports")

		err := Check(Config{Trivy: Trivy{
			CacheDir:   "",
			ReportsDir: reportsDir,
		}})

		assert.EqualError(t, err, "trivy cache dir must not be blank")
	})

	t.Run("Should return error when trivy reports dir is blank", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheDir := path.Join(tempDir, "cache")

		err := Check(Config{Trivy: Trivy{
			CacheDir:   cacheDir,
			ReportsDir: "",
		}})

		assert.EqualError(t, err, "trivy reports dir must not be blank")
	})

	t.Run("Should create trivy directories", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheDir := path.Join(tempDir, "cache")
		reportsDir := path.Join(tempDir, "reports")

		err := Check(Config{Trivy: Trivy{
			CacheDir:   cacheDir,
			ReportsDir: reportsDir,
		}})

		assert.NoError(t, err)
		assert.True(t, dirExists(cacheDir))
		assert.True(t, dirExists(reportsDir))
	})

	t.Run("Should skip creating trivy directories", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheDir := path.Join(tempDir, "cache")
		reportsDir := path.Join(tempDir, "reports")

		err := os.Mkdir(cacheDir, 0755)
		require.NoError(t, err)
		err = os.Mkdir(reportsDir, 0755)
		require.NoError(t, err)

		err = Check(Config{Trivy: Trivy{
			CacheDir:   cacheDir,
			ReportsDir: reportsDir,
		}})
		assert.NoError(t, err)
	})

	t.Run("Should return error when TLS certificate does not exist", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheDir := path.Join(tempDir, "cache")
		reportsDir := path.Join(tempDir, "reports")
		certFile := path.Join(tempDir, "tls.crt")
		keyFile := path.Join(tempDir, "tls.key")

		f, err := os.Create(keyFile)
		require.NoError(t, err)
		_ = f.Close()

		err = Check(Config{
			API: API{
				TLSCertificate: certFile,
				TLSKey:         keyFile,
			},
			Trivy: Trivy{
				CacheDir:   cacheDir,
				ReportsDir: reportsDir,
			},
		})
		assert.EqualError(t, err, fmt.Sprintf("TLS certificate file does not exist: %s", certFile))
	})

	t.Run("Should return error when TLS key does not exist", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheDir := path.Join(tempDir, "cache")
		reportsDir := path.Join(tempDir, "reports")
		certFile := path.Join(tempDir, "tls.crt")
		keyFile := path.Join(tempDir, "tls.key")

		f, err := os.Create(certFile)
		require.NoError(t, err)
		_ = f.Close()

		err = Check(Config{
			API: API{
				TLSCertificate: certFile,
				TLSKey:         keyFile,
			},
			Trivy: Trivy{
				CacheDir:   cacheDir,
				ReportsDir: reportsDir,
			},
		})
		assert.EqualError(t, err, fmt.Sprintf("TLS private key file does not exist: %s", keyFile))
	})

	t.Run("Should return error when one of ClientCAs does not exist", func(t *testing.T) {
		tempDir := t.TempDir()

		cacheDir := path.Join(tempDir, "cache")
		reportsDir := path.Join(tempDir, "reports")
		certFile := path.Join(tempDir, "tls.crt")
		keyFile := path.Join(tempDir, "tls.key")
		clientCA1File := path.Join(tempDir, "clientCA1.crt")
		clientCA2File := path.Join(tempDir, "clientCA2.crt")
		clientCA3File := path.Join(tempDir, "clientCA3.crt")

		f, err := os.Create(certFile)
		require.NoError(t, err)
		_ = f.Close()

		f, err = os.Create(keyFile)
		require.NoError(t, err)
		_ = f.Close()

		f, err = os.Create(clientCA1File)
		require.NoError(t, err)
		_ = f.Close()

		f, err = os.Create(clientCA3File)
		require.NoError(t, err)
		_ = f.Close()

		err = Check(Config{
			API: API{
				TLSCertificate: certFile,
				TLSKey:         keyFile,
				ClientCAs:      []string{clientCA1File, clientCA2File, clientCA3File},
			},
			Trivy: Trivy{
				CacheDir:   cacheDir,
				ReportsDir: reportsDir,
			},
		})

		assert.EqualError(t, err, fmt.Sprintf("ClientCA file does not exist: %s", clientCA2File))
	})
}
