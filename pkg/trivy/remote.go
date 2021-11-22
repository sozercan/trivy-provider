package trivy

import (
	"context"
	"time"

	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	fimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
)

func InitializeDockerScanner(ctx context.Context, imageName string, customHeaders client.CustomHeaders, url client.RemoteURL, timeout time.Duration) (scanner.Scanner, func(), error) {
	scannerScanner := client.NewProtobufClient(url)
	clientScanner := client.NewScanner(customHeaders, scannerScanner)
	artifactCache := cache.NewRemoteCache(cache.RemoteURL(url), nil)
	dockerOption, err := types.GetDockerOption(timeout)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	imageImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}

	artifactOpt := artifact.Option{
		SkipFiles: []string{},
		SkipDirs:  []string{},
	}
	artifact, err := fimage.NewArtifact(imageImage, artifactCache, artifactOpt, config.ScannerOption{})
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scanner2 := scanner.NewScanner(clientScanner, artifact)
	return scanner2, func() {
		cleanup()
	}, nil
}
