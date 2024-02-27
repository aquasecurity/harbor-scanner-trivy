//go:build component

package component

import (
	"context"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/test/component/docker"
	"github.com/aquasecurity/harbor-scanner-trivy/test/component/scanner"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	trivyScanner = harbor.Scanner{
		Name:    "Trivy",
		Vendor:  "Aqua Security",
		Version: "0.49.1",
	}
)

const (
	testNetwork = "component_test"
)

const (
	registryImage       = "registry:2"
	registryPort        = "5443/tcp"
	registryInternalURL = "https://registry:5443"
	registryUsername    = "testuser"
	registryPassword    = "testpassword"
)

const (
	adapterImage = "aquasec/harbor-scanner-trivy:dev"
	adapterPort  = "8080/tcp"
)

type LogConsumer struct {
	Msgs []string
}

func (g *LogConsumer) Accept(l tc.Log) {
	g.Msgs = append(g.Msgs, string(l.Content))
}

func TestComponent(t *testing.T) {
	if testing.Short() {
		t.Skip("A component test")
	}

	baseDir, err := filepath.Abs(".")
	require.NoError(t, err)

	ctx := context.TODO()
	dp, err := tc.NewDockerProvider()
	require.NoError(t, err)
	nt, err := dp.CreateNetwork(ctx, tc.NetworkRequest{
		Name: testNetwork,
	})
	require.NoError(t, err)
	defer func() { _ = nt.Remove(ctx) }()

	redisC, err := dp.CreateContainer(ctx,
		tc.ContainerRequest{
			Name:       "redis",
			Image:      "redis:5",
			Networks:   []string{testNetwork},
			WaitingFor: wait.ForLog("Ready to accept connections"),
		})
	require.NoError(t, err)
	err = redisC.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = redisC.Terminate(ctx) }()
	registryC, err := dp.CreateContainer(ctx,
		tc.ContainerRequest{
			Name:         "registry",
			Image:        registryImage,
			Networks:     []string{testNetwork},
			ExposedPorts: []string{registryPort},
			Env: map[string]string{
				"REGISTRY_HTTP_ADDR":            "0.0.0.0:5443",
				"REGISTRY_HTTP_TLS_CERTIFICATE": "/certs/cert.pem",
				"REGISTRY_HTTP_TLS_KEY":         "/certs/key.pem",
				"REGISTRY_AUTH":                 "htpasswd",
				"REGISTRY_AUTH_HTPASSWD_PATH":   "/auth/htpasswd",
				"REGISTRY_AUTH_HTPASSWD_REALM":  "Registry Realm",
			},
			Mounts: tc.ContainerMounts{
				tc.BindMount(filepath.Join(baseDir, "data", "registry", "certs"), "/certs"),
				tc.BindMount(filepath.Join(baseDir, "data", "registry", "auth"), "/auth"),
			},
			WaitingFor: wait.ForLog("listening on [::]:5443"),
		})

	require.NoError(t, err)
	err = registryC.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = registryC.Terminate(ctx) }()

	adapterC, err := dp.CreateContainer(ctx, tc.ContainerRequest{
		Name:         "trivy-adapter",
		Image:        adapterImage,
		Networks:     []string{testNetwork},
		ExposedPorts: []string{adapterPort},
		Env: map[string]string{
			"SCANNER_LOG_LEVEL":      "trace",
			"SCANNER_REDIS_URL":      "redis://redis:6379",
			"SCANNER_TRIVY_INSECURE": "true",
		},
		WaitingFor: wait.ForLog("Starting API server without TLS"),
	})
	require.NoError(t, err)
	err = adapterC.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = adapterC.Terminate(ctx) }()

	adapterLogs := &LogConsumer{}
	err = adapterC.StartLogProducer(ctx)
	require.NoError(t, err)
	defer func() {
		_ = adapterC.StopLogProducer()
		if t.Failed() {
			t.Logf("adatper logs\n%v", adapterLogs.Msgs)
		}
	}()
	adapterC.FollowOutput(adapterLogs)

	registryExternalURL, err := GetRegistryExternalURL(registryC, registryPort)
	require.NoError(t, err)

	adapterURL, err := GetAdapterURL(adapterC, adapterPort)
	require.NoError(t, err)

	config := docker.RegistryConfig{
		URL:      registryExternalURL,
		Username: registryUsername,
		Password: registryPassword,
	}

	const (
		repository = "alpine"
		tag        = "3.14"
	)
	imageRef := fmt.Sprintf("%s:%s", repository, tag)

	// 0. Download a test image from DockerHub, tag it and push to the test registry.
	artifactDigest, err := docker.ReplicateImage(imageRef, config)
	require.NoError(t, err)

	artifact := harbor.Artifact{
		Repository: repository,
		Digest:     artifactDigest.String(),
	}

	t.Run("scan image for vulnerabilities", func(t *testing.T) {
		c := scanner.NewClient(adapterURL)

		// 1. Send ScanRequest to Scanner Adapter.
		resp, err := c.RequestScan(harbor.ScanRequest{
			Registry: harbor.Registry{
				URL:           registryInternalURL,
				Authorization: config.GetBasicAuthorization(),
			},
			Artifact: artifact,
		})
		require.NoError(t, err)

		// 2. Poll Scanner Adapter for ScanReport.
		report, err := c.GetScanReport(resp.ID, api.MimeTypeSecurityVulnerabilityReport.String(), "")
		require.NoError(t, err)

		assert.Equal(t, artifact, report.Artifact)
		assert.Equal(t, trivyScanner, report.Scanner)
		// TODO Adding asserts on CVEs is tricky as we do not have any control over upstream vulnerabilities database used by Trivy.
		for _, v := range report.Vulnerabilities {
			t.Logf("ID %s, Package: %s, Version: %s, Severity: %s", v.ID, v.Pkg, v.Version, v.Severity)
		}
	})

	t.Run("scan image for SBOM", func(t *testing.T) {
		c := scanner.NewClient(adapterURL)
		// 1. Send ScanRequest to Scanner Adapter.
		resp, err := c.RequestScan(harbor.ScanRequest{
			Registry: harbor.Registry{
				URL:           registryInternalURL,
				Authorization: config.GetBasicAuthorization(),
			},
			Artifact: artifact,
			Capabilities: []harbor.Capability{
				{
					Type: harbor.CapabilityTypeSBOM,
					ProducesMIMETypes: []api.MIMEType{
						api.MimeTypeSecuritySBOMReport,
					},
					Parameters: &harbor.CapabilityAttributes{
						SBOMMediaTypes: []api.MediaType{
							api.MediaTypeSPDX,
						},
					},
				},
			},
		})
		require.NoError(t, err)

		// 2. Poll Scanner Adapter for ScanReport.
		report, err := c.GetScanReport(resp.ID, api.MimeTypeSecuritySBOMReport.String(), string(api.MediaTypeSPDX))
		require.NoError(t, err)

		assert.Equal(t, artifact, report.Artifact)
		assert.Equal(t, trivyScanner, report.Scanner)
		assert.Equal(t, api.MediaTypeSPDX, report.MediaType)
		assert.NotEmpty(t, report.SBOM)
	})

	if t.Failed() {
		time.Sleep(15 * time.Second)
	}
}

func GetRegistryExternalURL(registry tc.Container, exposedPort nat.Port) (*url.URL, error) {
	port, err := registry.MappedPort(context.TODO(), exposedPort)
	if err != nil {
		return nil, err
	}
	return url.Parse(fmt.Sprintf("https://localhost:%d", port.Int()))
}

func GetAdapterURL(adapter tc.Container, exposedPort nat.Port) (string, error) {
	port, err := adapter.MappedPort(context.TODO(), exposedPort)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://localhost:%d", port.Int()), nil
}
