package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	fimage "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/image"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

const outputType = "json"

var log logr.Logger

func main() {
	fmt.Println("starting server...")
	http.HandleFunc("/validate", validate)

    zapLog, err := zap.NewDevelopment()
    if err != nil {
        panic(fmt.Sprintf("unable to initialize logger: %v", err))
    }
    log = zapr.NewLogger(zapLog)

    log.Info("Logr in action!", "the answer", 42)

	if err = http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)
	defer cancel()

	image := string(body)
	remote := os.Getenv("REMOTE_URL")

	sc, cleanUp, err := initializeDockerScanner(ctx, image, client.CustomHeaders{}, client.RemoteURL(remote), time.Second*5000)
	if err != nil {
		log.Error(err, "could not initialize scanner")
		return
	}

	defer cleanUp()

	results, err := sc.ScanArtifact(ctx, types.ScanOptions{
		VulnType:            []string{"os", "library"},
		ScanRemovedPackages: true,
		ListAllPackages:     true,
	})
	if err != nil {
		log.Error(err, "could not scan image")
	}

	if len(results) > 0 {
		log.Info("%d vulnerability/ies found", len(results[0].Vulnerabilities))
		if err = report.WriteResults(outputType, os.Stdout, []dbTypes.Severity{dbTypes.SeverityUnknown}, results, "", false); err != nil {
			log.Error(err, "could not write results")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(len(results[0].Vulnerabilities))
	} else {
		log.Info("no vulnerabilities found for image %s", image)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(0)
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
	artifact := fimage.NewArtifact(imageImage, artifactCache, nil)
	scanner2 := scanner.NewScanner(clientScanner, artifact)
	return scanner2, func() {
		cleanup()
	}, nil
}
