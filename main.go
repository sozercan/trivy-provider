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
	"github.com/davecgh/go-spew/spew"
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
	log.WithName("trivy-provider")

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

	log.Info("validate", "image", image, "remote", remote)

	sc, cleanUp, err := initializeDockerScanner(ctx, image, client.CustomHeaders{}, client.RemoteURL(remote), time.Second*5000)
	if err != nil {
		log.Error(err, "unable to initialize scanner")
		return
	}

	//spew.Dump(sc)

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
	}

	spew.Dump(report)

	log.Info("validate", "results", report.Results)

	if len(report.Results) > 0 {
		log.Info("validate", "vulnerabilities found", len(report.Results[0].Vulnerabilities))

		// reportOpts := report.Option {
		// 	Severities: []dbTypes.Severity{dbTypes.SeverityUnknown},
		// 	OutputTemplate: outputType,
		// }
		// if err = report.Write(results, reportOpts); err != nil {
		// 	log.Error(err, "could not write results")
		// }

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(len(report.Results[0].Vulnerabilities))
	} else {
		log.Info("validate", "no vulnerabilities found", image)

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
	artifact, err := fimage.NewArtifact(imageImage, artifactCache, nil, config.ScannerOption{})
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scanner2 := scanner.NewScanner(clientScanner, artifact)
	return scanner2, func() {
		cleanup()
	}, nil
}
