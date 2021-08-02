package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/aquasecurity/fanal/analyzer/config"
	fimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

var log logr.Logger

func main() {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("unable to initialize logger: %v", err))
	}
	log = zapr.NewLogger(zapLog)
	log.WithName("trivy-provider")

	log.Info("starting server...")
	http.HandleFunc("/validate", validate)

	if err = http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error(err, "unable to read request body")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)
	defer cancel()

	image := string(body)
	remote := os.Getenv("REMOTE_URL")

	log.Info("validate", "image", image, "remote", remote)

	sc, cleanUp, err := initializeDockerScanner(ctx, image, client.CustomHeaders{}, client.RemoteURL(remote), time.Second*5000)
	if err != nil {
		log.Error(err, "unable to initialize scanner")
		return
	}
	defer cleanUp()

	scanOpts := types.ScanOptions{
		VulnType:            []string{"os", "library"},
		SecurityChecks:      []string{"vuln", "config"},
		ScanRemovedPackages: true,
		ListAllPackages:     true,
		SkipFiles:           []string{},
		SkipDirs:            []string{},
	}
	report, err := sc.ScanArtifact(ctx, scanOpts)
	if err != nil {
		log.Error(err, "unable to scan image")
		return
	}

	if len(report.Results) > 0 {
		log.Info("validate", "vulnerabilities found", len(report.Results[0].Vulnerabilities))

		w.WriteHeader(http.StatusOK)
		if err = json.NewEncoder(w).Encode(len(report.Results[0].Vulnerabilities)); err != nil {
			log.Error(err, "unable to encode output")
			return
		}
	} else {
		log.Info("validate", "no vulnerabilities found", image)

		w.WriteHeader(http.StatusOK)
		if err = json.NewEncoder(w).Encode(0); err != nil {
			log.Error(err, "unable to encode output")
			return
		}
	}
}

func initializeDockerScanner(ctx context.Context, imageName string, customHeaders client.CustomHeaders, url client.RemoteURL, timeout time.Duration) (scanner.Scanner, func(), error) {
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
	artifact, err := fimage.NewArtifact(imageImage, artifactCache, nil, config.ScannerOption{})
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scanner2 := scanner.NewScanner(clientScanner, artifact)
	return scanner2, func() {
		cleanup()
	}, nil
}
