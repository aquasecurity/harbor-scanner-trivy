//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	fixtures "github.com/aquasecurity/bolt-fixtures"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/redisx"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/scan"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcr "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRestAPI is an integration test for the REST API adapter.
// Tests only happy paths. All branches are covered in the corresponding unit tests.
func TestRestAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}

	ctx := context.Background()
	now := time.Now()

	jobQueue := etc.JobQueue{
		Namespace:         "test:job-queue",
		WorkerConcurrency: 1,
	}

	// Set up Redis
	rdb, store := initRedis(t)
	enqueuer := queue.NewEnqueuer(jobQueue, rdb, store)

	// Set up Trivy
	wrapper, trivyConf := initTrivy(t, now)

	// Set up worker
	initWorker(t, ctx, store, jobQueue, rdb, wrapper)

	// Set up registry
	imageRef, sbomRef := initRegistry(t)

	app := v1.NewAPIHandler(
		etc.BuildInfo{
			Version: "1.0",
			Commit:  "abc",
			Date:    "2019-01-04T12:40",
		},
		etc.Config{Trivy: trivyConf}, enqueuer, store, wrapper)

	ts := httptest.NewServer(app)
	t.Cleanup(ts.Close)

	t.Run("Scan image for vulnerabilities", func(t *testing.T) {
		var scanJobID string
		t.Run("POST /api/v1/scan", func(t *testing.T) {
			// when
			body := harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: imageRef.Registry.Scheme() + "://" + imageRef.RegistryStr(),
				},
				Artifact: harbor.Artifact{
					Repository: imageRef.RepositoryStr(),
					Digest:     imageRef.DigestStr(),
				},
			}
			buf := &bytes.Buffer{}
			err := json.NewEncoder(buf).Encode(body)
			require.NoError(t, err)
			rs, err := ts.Client().Post(ts.URL+"/api/v1/scan", "application/json", buf)

			// then
			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, rs.StatusCode)
			assert.Equal(t, "application/vnd.scanner.adapter.scan.response+json; version=1.0", rs.Header.Get("Content-Type"))

			var res harbor.ScanResponse
			err = json.NewDecoder(rs.Body).Decode(&res)
			require.NoError(t, err)
			assert.NotEmpty(t, res.ID)

			scanJobID = res.ID
		})

		t.Run("GET /api/v1/scan/{scan_request_id}/report", func(t *testing.T) {
			time.Sleep(3 * time.Second)

			rs, err := ts.Client().Get(fmt.Sprintf("%s/api/v1/scan/%s/report", ts.URL, scanJobID))
			require.NoError(t, err)
			defer rs.Body.Close()

			// then
			assert.Equal(t, http.StatusOK, rs.StatusCode)
			assert.Equal(t, "application/vnd.security.vulnerability.report; version=1.1", rs.Header.Get("Content-Type"))

			// Parse response body
			var got harbor.ScanReport
			err = json.NewDecoder(rs.Body).Decode(&got)
			require.NoError(t, err)
			got.GeneratedAt = time.Time{}

			want := harbor.ScanReport{
				Artifact: harbor.Artifact{
					Repository: imageRef.RepositoryStr(),
					Digest:     imageRef.DigestStr(),
				},
				Scanner: harbor.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "Unknown",
				},
				Severity: harbor.SevMedium,
				Vulnerabilities: []harbor.VulnerabilityItem{
					{
						ID:          "CVE-2020-28928",
						Pkg:         "musl",
						Version:     "1.1.22-r4",
						FixVersion:  "1.1.22-r5",
						Severity:    harbor.SevMedium,
						Description: "In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).",
						Links: []string{
							"https://avd.aquasec.com/nvd/cve-2020-28928",
						},
						Layer: &harbor.Layer{
							Digest: "sha256:26d14edc4f17638cda363ea80b29c55e83058fc0dff1129b38ea3e8231217f7d",
							DiffID: "sha256:e484d53633e7e5ebaabbe277838af1f26c388cbcebfa32e29fae72dd4086d54d",
						},
					},
					{
						ID:          "CVE-2020-28928",
						Pkg:         "musl-utils",
						Version:     "1.1.22-r4",
						FixVersion:  "1.1.22-r5",
						Severity:    harbor.SevMedium,
						Description: "In musl libc through 1.2.1, wcsnrtombs mishandles particular combinations of destination buffer size and source character limit, as demonstrated by an invalid write access (buffer overflow).",
						Links: []string{
							"https://avd.aquasec.com/nvd/cve-2020-28928",
						},
						Layer: &harbor.Layer{
							Digest: "sha256:26d14edc4f17638cda363ea80b29c55e83058fc0dff1129b38ea3e8231217f7d",
							DiffID: "sha256:e484d53633e7e5ebaabbe277838af1f26c388cbcebfa32e29fae72dd4086d54d",
						},
					},
				},
			}

			assert.Equal(t, want, got)
		})
	})

	t.Run("Scan image for SBOM", func(t *testing.T) {
		var scanJobID string
		t.Run("POST /api/v1/scan", func(t *testing.T) {
			// when
			body := harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: imageRef.Registry.Scheme() + "://" + imageRef.RegistryStr(),
				},
				Artifact: harbor.Artifact{
					Repository: imageRef.RepositoryStr(),
					Digest:     imageRef.DigestStr(),
				},
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
			}
			buf := &bytes.Buffer{}
			err := json.NewEncoder(buf).Encode(body)
			require.NoError(t, err)
			rs, err := ts.Client().Post(ts.URL+"/api/v1/scan", "application/json", buf)

			// then
			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, rs.StatusCode)
			assert.Equal(t, "application/vnd.scanner.adapter.scan.response+json; version=1.0", rs.Header.Get("Content-Type"))

			var res harbor.ScanResponse
			err = json.NewDecoder(rs.Body).Decode(&res)
			require.NoError(t, err)
			assert.NotEmpty(t, res.ID)

			scanJobID = res.ID
		})

		t.Run("GET /api/v1/scan/{scan_request_id}/report", func(t *testing.T) {
			time.Sleep(3 * time.Second)

			values := url.Values{}
			values.Add("sbom_media_type", "application/spdx+json")
			req, err := http.NewRequest("GET",
				fmt.Sprintf("%s/api/v1/scan/%s/report?", ts.URL, scanJobID)+values.Encode(), nil)
			require.NoError(t, err)
			req.Header.Add("Accept", "application/vnd.security.sbom.report+json; version=1.0")
			rs, err := ts.Client().Do(req)
			require.NoError(t, err)

			// then
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, rs.StatusCode)
			assert.Equal(t, "application/vnd.security.sbom.report+json; version=1.0", rs.Header.Get("Content-Type"))

			var got harbor.ScanReport
			err = json.NewDecoder(rs.Body).Decode(&got)
			require.NoError(t, err)
			assert.NotEmpty(t, got.SBOM)

			got.GeneratedAt = time.Time{}
			got.SBOM = nil

			want := harbor.ScanReport{
				Artifact: harbor.Artifact{
					Repository: imageRef.RepositoryStr(),
					Digest:     imageRef.DigestStr(),
				},
				Scanner: harbor.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "Unknown",
				},
				MediaType: api.MediaTypeSPDX,
			}
			assert.Equal(t, want, got)
		})
	})

	t.Run("Scan SBOM for vulnerabilities", func(t *testing.T) {
		var scanJobID string
		t.Run("POST /api/v1/scan", func(t *testing.T) {
			// when
			body := harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: sbomRef.Registry.Scheme() + "://" + sbomRef.RegistryStr(),
				},
				Artifact: harbor.Artifact{
					Repository: "testimage",
					Digest:     sbomRef.DigestStr(),
				},
				Capabilities: []harbor.Capability{
					{
						Type: harbor.CapabilityTypeVulnerability,
						ProducesMIMETypes: []api.MIMEType{
							api.MimeTypeSecurityVulnerabilityReport,
						},
					},
				},
			}
			buf := &bytes.Buffer{}
			err := json.NewEncoder(buf).Encode(body)
			require.NoError(t, err)

			rs, err := ts.Client().Post(ts.URL+"/api/v1/scan", "application/json", buf)

			// then
			require.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, rs.StatusCode)
			assert.Equal(t, "application/vnd.scanner.adapter.scan.response+json; version=1.0", rs.Header.Get("Content-Type"))

			var res harbor.ScanResponse
			err = json.NewDecoder(rs.Body).Decode(&res)
			require.NoError(t, err)
			assert.NotEmpty(t, res.ID)

			scanJobID = res.ID
		})

		t.Run("GET /api/v1/scan/{scan_request_id}/report", func(t *testing.T) {
			time.Sleep(3 * time.Second)
			rs, err := ts.Client().Get(fmt.Sprintf("%s/api/v1/scan/%s/report", ts.URL, scanJobID))
			require.NoError(t, err)
			defer rs.Body.Close()

			// then
			assert.Equal(t, http.StatusOK, rs.StatusCode)
			assert.Equal(t, "application/vnd.security.vulnerability.report; version=1.1", rs.Header.Get("Content-Type"))

			var got harbor.ScanReport
			err = json.NewDecoder(rs.Body).Decode(&got)
			require.NoError(t, err)
			got.GeneratedAt = time.Time{} // ignore generated_at

			want := harbor.ScanReport{
				Artifact: harbor.Artifact{
					Repository: "testimage",
					Digest:     sbomRef.DigestStr(),
				},
				Scanner: harbor.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "Unknown",
				},
				Severity: harbor.SevMedium,
				Vulnerabilities: []harbor.VulnerabilityItem{
					{
						ID:          "CVE-2019-1549",
						Pkg:         "libssl1.1",
						Version:     "1.1.1c-r0",
						FixVersion:  "1.1.1d-r0",
						Severity:    harbor.SevMedium,
						Description: "OpenSSL 1.1.1 introduced a rewritten random number generator (RNG). This was intended to include protection in the event of a fork() system call in order to ensure that the parent and child processes did not share the same RNG state. However this protection was not being used in the default case. A partial mitigation for this issue is that the output from a high precision timer is mixed into the RNG state so the likelihood of a parent and child process sharing state is significantly reduced. If an application already calls OPENSSL_init_crypto() explicitly using OPENSSL_INIT_ATFORK then this problem does not occur at all. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c).",
						Links: []string{
							"https://avd.aquasec.com/nvd/cve-2019-1549",
						},
						VendorAttributes: map[string]any{
							"CVSS": map[string]any{
								"nvd": map[string]any{
									"V3Score":  5.3,
									"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
								},
							},
						},
						Layer: &harbor.Layer{},
					},
				},
			}
			assert.Equal(t, want, got)
		})
	})

	t.Run("GET /api/v1/metadata", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/api/v1/metadata")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)

		bodyBytes, err := io.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, fmt.Sprintf(`{
  "scanner": {
    "name": "Trivy",
    "vendor": "Aqua Security",
    "version": "Unknown"
  },
  "capabilities": [
    {
      "type": "vulnerability",
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.security.vulnerability.report; version=1.1"
      ]
    },
    {
      "type": "sbom",
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.security.sbom.report+json; version=1.0"
      ],
      "additional_attributes": {
        "sbom_media_types": [
          "application/spdx+json",
          "application/vnd.cyclonedx+json"
        ]
      }
    }
  ],
  "properties": {
	"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
	"harbor.scanner-adapter/vulnerability-database-updated-at": "%s",
	"org.label-schema.version": "1.0",
	"org.label-schema.build-date": "2019-01-04T12:40",
	"org.label-schema.vcs-ref": "abc",
	"org.label-schema.vcs": "https://github.com/aquasecurity/harbor-scanner-trivy",
	"env.SCANNER_TRIVY_SKIP_UPDATE": "true",
	"env.SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE": "true",
	"env.SCANNER_TRIVY_OFFLINE_SCAN": "false",
	"env.SCANNER_TRIVY_IGNORE_UNFIXED": "true",
	"env.SCANNER_TRIVY_DEBUG_MODE": "true",
	"env.SCANNER_TRIVY_INSECURE": "true",
	"env.SCANNER_TRIVY_VULN_TYPE": "os",
	"env.SCANNER_TRIVY_SEVERITY": "LOW,MEDIUM,HIGH,CRITICAL",
	"env.SCANNER_TRIVY_SECURITY_CHECKS": "vuln",
	"env.SCANNER_TRIVY_TIMEOUT": "5m0s"
	}
}`,
			now.UTC().Format(time.RFC3339)),
			string(bodyBytes))
	})

	t.Run("GET /probe/healthy", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/probe/healthy")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
	})

	t.Run("GET /probe/ready", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/probe/ready")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
	})
}

func initRedis(t *testing.T) (*goredis.Client, persistence.Store) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	rdb, err := redisx.NewClient(etc.RedisPool{
		URL: "redis://" + mr.Addr(),
	})
	require.NoError(t, err)

	store := redis.NewStore(etc.RedisStore{
		Namespace:  "test:data-store",
		ScanJobTTL: 5 * time.Minute,
	}, rdb)

	return rdb, store
}

func initTrivy(t *testing.T, now time.Time) (trivy.Wrapper, etc.Trivy) {
	cacheDir := initVulnDB(t, now)
	trivyConf := etc.Trivy{
		CacheDir:         cacheDir,
		SkipDBUpdate:     true,
		SkipJavaDBUpdate: true,
		Insecure:         true,
		Timeout:          5 * time.Minute,
		Severity:         "LOW,MEDIUM,HIGH,CRITICAL",
		VulnType:         "os",
		Scanners:         "vuln",
		IgnoreUnfixed:    true,
		DebugMode:        true,
	}
	wrapper := trivy.NewWrapper(trivyConf, ext.DefaultAmbassador)

	return wrapper, trivyConf
}

func initVulnDB(t *testing.T, now time.Time) string {
	fixtureDir := filepath.Join("testdata", "fixtures")
	entries, err := os.ReadDir(fixtureDir)
	require.NoError(t, err)

	var fixtureFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fixtureFiles = append(fixtureFiles, filepath.Join(fixtureDir, entry.Name()))
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db", "trivy.db")
	dbDir := filepath.Dir(dbPath)
	err = os.MkdirAll(dbDir, 0700)
	require.NoError(t, err)

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	require.NoError(t, err)
	require.NoError(t, loader.Load())
	require.NoError(t, loader.Close())

	// Generate metadata.json
	metadataFile := filepath.Join(dbDir, "metadata.json")
	f, err := os.Create(metadataFile)
	require.NoError(t, err)
	defer f.Close()

	metadata := struct {
		Version      int
		NextUpdate   time.Time
		UpdatedAt    time.Time
		DownloadedAt time.Time
	}{
		Version:      2,
		NextUpdate:   now.Add(24 * time.Hour),
		UpdatedAt:    now,
		DownloadedAt: now,
	}
	err = json.NewEncoder(f).Encode(metadata)
	require.NoError(t, err)

	return dir
}

func initWorker(t *testing.T, ctx context.Context, store persistence.Store, jobQueue etc.JobQueue,
	rdb *goredis.Client, wrapper trivy.Wrapper) {
	controller := scan.NewController(store, wrapper, scan.NewTransformer(&scan.SystemClock{}))
	worker := queue.NewWorker(jobQueue, rdb, controller)
	t.Cleanup(worker.Stop)

	worker.Start(ctx)
}

func initRegistry(t *testing.T) (name.Digest, name.Digest) {
	reg := httptest.NewServer(registry.New())

	regURL, err := url.Parse(reg.URL)
	require.NoError(t, err)

	return setupTestImage(t, regURL), setupTestSBOM(t, regURL)
}

func setupTestImage(t *testing.T, reg *url.URL) name.Digest {
	const src = "alpine@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98" // alpine:3.10
	dst, err := name.NewTag(reg.Host + "/testimage:latest")
	require.NoError(t, err)
	err = crane.Copy(src, dst.String(), crane.WithPlatform(&ggcr.Platform{
		OS:           "linux",
		Architecture: runtime.GOARCH,
	}))
	require.NoError(t, err)

	img, err := remote.Image(dst)
	require.NoError(t, err)

	d, err := img.Digest()
	require.NoError(t, err)

	digest, err := name.NewDigest(dst.Repository.Name() + "@" + d.String())
	require.NoError(t, err)

	return digest
}

func setupTestSBOM(t *testing.T, reg *url.URL) name.Digest {
	repo := reg.Host + "/testimage"
	ref, err := name.NewTag(repo + ":latest")
	require.NoError(t, err)

	// Make an image
	layer, err := tarball.LayerFromFile("testdata/alpine.spdx")
	require.NoError(t, err)

	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
	})
	require.NoError(t, err)

	img = mutate.ArtifactType(img, "application/vnd.goharbor.harbor.sbom.v1")

	// Push
	err = remote.Write(ref, img)
	require.NoError(t, err)

	digest, err := img.Digest()
	require.NoError(t, err)

	d, err := name.NewDigest(repo + "@" + digest.String())
	require.NoError(t, err)

	return d
}
