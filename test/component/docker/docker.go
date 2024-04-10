//go:build component
// +build component

package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	apiregistry "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/opencontainers/go-digest"
	"io"
	"net/url"
)

type RegistryConfig struct {
	URL      *url.URL
	Username string
	Password string
}

func (c RegistryConfig) GetRegistryAuth() (auth string, err error) {
	authConfig := apiregistry.AuthConfig{
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

// ReplicateImage tags the given imageRef and pushes it to the given dest registry.
func ReplicateImage(imageRef string, dest RegistryConfig) (d digest.Digest, err error) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return
	}
	pullOut, err := cli.ImagePull(ctx, imageRef, types.ImagePullOptions{})
	defer func() {
		_ = pullOut.Close()
	}()

	_, err = io.Copy(io.Discard, pullOut)
	if err != nil {
		return
	}

	targetImageRef := fmt.Sprintf("%s:%s/%s", dest.URL.Hostname(), dest.URL.Port(), imageRef)

	err = cli.ImageTag(ctx, imageRef, targetImageRef)
	if err != nil {
		return
	}

	auth, err := dest.GetRegistryAuth()
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
	_, err = io.Copy(io.Discard, pushOut)
	inspect, err := cli.DistributionInspect(ctx, targetImageRef, auth)
	if err != nil {
		return
	}
	d = inspect.Descriptor.Digest
	return
}
