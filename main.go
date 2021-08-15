package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/sozercan/trivy-provider/pkg/trivy"
	"go.uber.org/zap"
)

var log logr.Logger

const timeout = 3 * time.Second

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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	image := string(body)
	remote := os.Getenv("REMOTE_URL")

	log.Info("validate", "image", image, "remote", remote)

	s, cleanup, err := trivy.InitializeDockerScanner(ctx, image, client.CustomHeaders{}, client.RemoteURL(remote), timeout)
	if err != nil {
		log.Error(err, "unable to initialize scanner")
		return
	}
	defer cleanup()

	scanOpts := types.ScanOptions{
		VulnType:            []string{"os", "library"},
		SecurityChecks:      []string{"vuln", "config"},
		ScanRemovedPackages: true,
		ListAllPackages:     true,
		SkipFiles:           []string{},
		SkipDirs:            []string{},
	}
	report, err := s.ScanArtifact(ctx, scanOpts)
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
