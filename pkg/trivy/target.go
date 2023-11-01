package trivy

import (
	"crypto/tls"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
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
	v1.Image

	ref  ImageRef
	Type Target
}

func newTarget(imageRef ImageRef, config etc.Trivy) (ScanTarget, error) {
	var nameOpts []name.Option
	slog.Info("newTarget",
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

	img, err := remote.Image(ref, authOpt, trOpt)
	if err != nil {
		return ScanTarget{}, xerrors.Errorf("fetching image: %w", err)
	}

	target := ScanTarget{
		Image: img,
		ref:   imageRef,
	}

	m, err := target.Manifest()
	if err != nil {
		return ScanTarget{}, xerrors.Errorf("getting image manifest: %w", err)
	}

	switch m.ArtifactType {
	case "application/vnd.goharbor.harbor.sbom.v1":
		target.Type = TargetSBOM
	default:
		target.Type = TargetImage
	}

	return target, nil
}

func (t ScanTarget) Name() (string, error) {
	switch t.Type {
	case TargetSBOM:
		return t.downloadSBOM()
	case TargetImage:
		return t.ref.Name, nil
	default:
		return "", xerrors.Errorf("invalid target type %s", t.Type)
	}
}

func (t ScanTarget) NonSSL() bool {
	return t.ref.NonSSL
}

func (t ScanTarget) Auth() RegistryAuth {
	switch t.Type {
	case TargetSBOM:
		return NoAuth{}
	case TargetImage:
		return t.ref.Auth
	default:
		return NoAuth{}
	}
}

func (t ScanTarget) downloadSBOM() (string, error) {
	layers, err := t.Layers()
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

	sbomFile, err := os.CreateTemp("", "sbom_*.json")
	if err != nil {
		return "", xerrors.Errorf("create temp file: %w", err)
	}
	defer sbomFile.Close()

	if _, err = io.Copy(sbomFile, r); err != nil {
		return "", xerrors.Errorf("copy layer to temp file: %w", err)
	}

	return sbomFile.Name(), nil
}
