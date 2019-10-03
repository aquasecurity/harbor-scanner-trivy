# Releases

This document is intended for maintainers only.

## TOC

- [Prerequisites](#prerequisites)
- [Build and test the next release locally](#build-and-test-the-next-release-locally)
- [Release a new version](#release-a-new-version)
- [Release artifacts](#release-artifacts)

## Prerequisites

1. Install [GoReleaser](https://goreleaser.com/) or use it as curl bash piping:
   ```
   $ brew install goreleaser/tap/goreleaser
   $ goreleaser -v
   ```
   ```
   $ curl -sL https://git.io/goreleaser | bash -s -- -v
   ```
2. Fork and clone this repository and then add the `upstream` remote repository:
   ```
   $ git remote -v
   origin    git@github.com:<YOUR_GITHUB_USERNAME>/harbor-scanner-trivy.git (fetch)
   origin    git@github.com:<YOUR_GITHUB_USERNAME>/harbor-scanner-trivy.git (push)
   upstream  git@github.com:aquasecurity/harbor-scanner-trivy.git (fetch)
   upstream  git@github.com:aquasecurity/harbor-scanner-trivy.git (push)
   ```
3. Docker client connected to a Docker host:
   ```
   $ docker info
   ```

### Environment

GoReleaser requires the following environment variables to be set.

| Environment Variable | Description |
|----------------------|-------------|
| `GITHUB_TOKEN`       | GitHub API token with the `repo` scope to deploy the artifacts to GitHub |
| `DOCKERHUB_USER`     | DockerHub username |
| `DOCKERHUB_TOKEN`    | DockerHub access token to push images |

Those can be stored as encrypted environment variable in `.travis.yml`. The easiest way to encrypt something with the
public key is to use Travis CLI:

```
$ gem install travis
```

```
$ travis encrypt GITHUB_TOKEN="***" --repo aquasecurity/harbor-scanner-trivy
$ travis encrypt DOCKERHUB_USER="***" --repo aquasecurity/harbor-scanner-trivy
$ travis encrypt DOCKERHUB_TOKEN="***" --repo aquasecurity/harbor-scanner-trivy
```

## Build and test the next release locally

1. Make sure that your fork's `master` branch is up to date with `upstream/master` and your working tree is clean.
2. Run unit tests and make sure that they're passing:
   ```
   $ make test
   ```
3. Perform a dry run to test everything before doing a release for real. Notice the `--skip-publish` flag, which
   instructs GoReleaser to only build and package things:
   ```
   $ goreleaser --snapshot --skip-publish --rm-dist
   ```
4. Make sure that the Docker image was built successfully:
   ```
   $ docker image inspect "docker.io/aquasec/harbor-scanner-trivy:$CURRENT_VERSION-next"
   ```
   where `CURRENT_VERSION` corresponds to the latest release tag, e.g. `v0.1.0` or equals `v0.0.0` if you're releasing
   for the first time.
5. You can even try running the container to be more confident with new release:
   ```
   $ docker container run --rm -p 8080:8080 "docker.io/aquasec/harbor-scanner-trivy:$CURRENT_VERSION-next"
   ```

## Release a new version

1. If everything is fine so far create an annotated git tag and push it to the `upstream` repository to actually
   trigger the release build:
   ```
   $ git tag -a $NEW_VERSION -m "Release $NEW_VERSION"
   $ git push upstream $NEW_VERSION
   ```
   where `NEW_VERSION` adheres to semantic versioning, e.g. `v0.2.0`.
2. Check that Travis CI scheduled a build job that corresponds to `NEW_VERSION`. Make sure that the job exited with 0 status code.

## Release artifacts

1. Make sure that GoReleaser uploaded artifacts to GitHub [releases](https://github.com/aquasecurity/harbor-scanner-trivy/releases) page.
2. Make sure that GoReleaser pushed new tag `NEW_VERSION` to Docker Hub [repository](https://hub.docker.com/r/aquasec/harbor-scanner-trivy/tags).
