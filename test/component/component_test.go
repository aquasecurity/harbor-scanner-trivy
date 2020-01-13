// +build component

package component

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/model/harbor"
	"github.com/caarlos0/env/v6"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"io"
	"os"
	"testing"
)

type Config struct {
	Registry           RegistryConfig
	ArtifactRepository string `env:"TEST_ARTIFACT_REPOSITORY" envDefault:"alpine"`
	ArtifactTag        string `env:"TEST_ARTIFACT_TAG" envDefault:"3.10.2"`
	ScannerURL         string `env:"TEST_SCANNER_URL" envDefault:"http://localhost:8080"`
}

type RegistryConfig struct {
	URL      string `env:"TEST_REGISTRY_URL" envDefault:"https://registry:5443"`
	Username string `env:"TEST_REGISTRY_USERNAME" envDefault:"testuser"`
	Password string `env:"TEST_REGISTRY_PASSWORD" envDefault:"testpassword"`
}

func (c RegistryConfig) GetRegistryAuth() (auth string, err error) {
	authConfig := types.AuthConfig{
		Username: c.Username,
		Password: c.Password,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	auth = base64.URLEncoding.EncodeToString(encodedJSON)
	return
}

func (c RegistryConfig) GetBasicAuthorization() string {
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Username, c.Password))))
}

// TestComponent is a component test for the whole adapter service.
// It should test only the shortest and happiest path to make sure that all pieces are nicely put together.
func TestComponent(t *testing.T) {
	if testing.Short() {
		t.Skip("A component test")
	}
	var config Config
	err := env.Parse(&config)
	require.NoError(t, err)

	imageRef := fmt.Sprintf("%s:%s", config.ArtifactRepository, config.ArtifactTag)

	// 1. Download a test image from DockerHub, retag it and push to the test registry.
	artifactDigest, err := tagAndPush(config.Registry, imageRef)
	require.NoError(t, err)

	req := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           config.Registry.URL,
			Authorization: config.Registry.GetBasicAuthorization(),
		},
		Artifact: harbor.Artifact{
			Repository: config.ArtifactRepository,
			Digest:     artifactDigest.String(),
		},
	}

	c := NewClient(config.ScannerURL)
	// 2. Send ScanRequest to Scanner Adapter.
	resp, err := c.RequestScan(req)
	require.NoError(t, err)

	// 3. Poll Scanner Adapter for ScanReport.
	report, err := c.GetScanReport(resp.ID)
	require.NoError(t, err)

	assert.Equal(t, req.Artifact, report.Artifact)
	assert.Equal(t, harbor.Scanner{Name: "Trivy", Vendor: "Aqua Security", Version: "0.4.2"}, report.Scanner)
	// TODO Adding asserts on CVEs is tricky as we do not have any control over upstream vulnerabilities database used by Trivy.
	for _, v := range report.Vulnerabilities {
		t.Logf("ID %s, Package: %s, Version: %s, Severity: %s", v.ID, v.Pkg, v.Version, v.Severity)
	}
}

// tagAndPush tags the given imageRef and pushes it to the given test registry.
func tagAndPush(config RegistryConfig, imageRef string) (d digest.Digest, err error) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return
	}
	pullOut, err := cli.ImagePull(ctx, imageRef, types.ImagePullOptions{})
	defer func() {
		_ = pullOut.Close()
	}()

	_, err = io.Copy(os.Stdout, pullOut)
	if err != nil {
		return
	}

	targetImageRef := fmt.Sprintf("%s/%s", "localhost:5443", imageRef)

	err = cli.ImageTag(ctx, imageRef, targetImageRef)
	if err != nil {
		return
	}

	auth, err := config.GetRegistryAuth()
	if err != nil {
		return
	}
	pushOut, err := cli.ImagePush(ctx, targetImageRef, types.ImagePushOptions{RegistryAuth: auth})
	if err != nil {
		return
	}
	defer func() {
		_ = pushOut.Close()
	}()
	_, err = io.Copy(os.Stdout, pushOut)
	inspect, err := cli.DistributionInspect(ctx, targetImageRef, auth)
	if err != nil {
		return
	}
	d = inspect.Descriptor.Digest
	return
}
