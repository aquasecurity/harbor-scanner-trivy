package trivy

import (
	"crypto/tls"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/xerrors"
	"io"
	"log/slog"
	"net/http"
	"os"
)

type Target string

const (
	TargetSBOM  Target = "sbom"
	TargetImage Target = "image"
)

type ScanTarget struct {
	img      v1.Image
	ref      ImageRef
	kind     Target
	filePath string // For SBOM
}

func newTarget(imageRef ImageRef, config etc.Trivy, ambassador ext.Ambassador) (ScanTarget, error) {
	var nameOpts []name.Option
	slog.Debug("newTarget",
		slog.Bool("nonssl", imageRef.NonSSL),
		slog.Bool("insecure", config.Insecure),
	)
	if imageRef.NonSSL {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageRef.Name, nameOpts...)
	if err != nil {
		return ScanTarget{}, xerrors.Errorf("parsing image reference: %w", err)
	}

	authOpt := remote.WithAuthFromKeychain(authn.DefaultKeychain)
	switch a := imageRef.Auth.(type) {
	case NoAuth:
	case BasicAuth:
		authOpt = remote.WithAuth(&authn.Basic{
			Username: a.Username,
			Password: a.Password,
		})
	case BearerAuth:
		authOpt = remote.WithAuth(&authn.Bearer{
			Token: a.Token,
		})
	default:
		return ScanTarget{}, xerrors.Errorf("invalid auth type %T", a)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.Insecure}
	trOpt := remote.WithTransport(tr)

	img, err := ambassador.RemoteImage(ref, authOpt, trOpt)
	if err != nil {
		return ScanTarget{}, xerrors.Errorf("fetching image: %w", err)
	}

	target := ScanTarget{
		img: img,
		ref: imageRef,
	}

	m, err := target.img.Manifest()
	if err != nil {
		return ScanTarget{}, xerrors.Errorf("getting image manifest: %w", err)
	}

	switch m.ArtifactType {
	case "application/vnd.goharbor.harbor.sbom.v1":
		target.kind = TargetSBOM
		if target.filePath, err = downloadSBOM(img, config.CacheDir, ambassador); err != nil {
			return ScanTarget{}, xerrors.Errorf("downloading SBOM: %w", err)
		}
	default:
		target.kind = TargetImage
	}

	return target, nil
}

func (t ScanTarget) Name() (string, error) {
	switch t.kind {
	case TargetSBOM:
		return t.filePath, nil
	case TargetImage:
		return t.ref.Name, nil
	default:
		return "", xerrors.Errorf("invalid target type %s", t.kind)
	}
}

func (t ScanTarget) NonSSL() bool {
	return t.ref.NonSSL
}

func (t ScanTarget) Auth() RegistryAuth {
	switch t.kind {
	case TargetSBOM:
		return NoAuth{}
	case TargetImage:
		return t.ref.Auth
	default:
		return NoAuth{}
	}
}

func (t ScanTarget) Clean() error {
	switch t.kind {
	case TargetSBOM:
		return os.Remove(t.filePath)
	default:
		return nil
	}
}

// downloadSBOM downloads the SBOM from the registry and returns the path to the downloaded file.
func downloadSBOM(img v1.Image, cacheDir string, ambassador ext.Ambassador) (string, error) {
	layers, err := img.Layers()
	if err != nil {
		return "", xerrors.Errorf("get image layers: %w", err)
	} else if len(layers) != 1 {
		return "", xerrors.Errorf("invalid number of layers: %d", len(layers))
	}

	r, err := layers[0].Uncompressed()
	if err != nil {
		return "", xerrors.Errorf("uncompress layer: %w", err)
	}
	defer r.Close()

	sbomFile, err := ambassador.TempFile(cacheDir, "sbom_*.json")
	if err != nil {
		return "", xerrors.Errorf("create temp file: %w", err)
	}
	defer sbomFile.Close()

	if _, err = io.Copy(sbomFile, r); err != nil {
		return "", xerrors.Errorf("copy layer to temp file: %w", err)
	}

	return sbomFile.Name(), nil
}
