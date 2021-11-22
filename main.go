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
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sozercan/trivy-provider/pkg/trivy"
	"go.uber.org/zap"
)

var log logr.Logger

const (
	timeout    = 3 * time.Second
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
)

func main() {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("unable to initialize logger: %v", err))
	}
	log = zapr.NewLogger(zapLog)
	log.WithName("trivy-provider")

	log.Info("starting server...")
	http.HandleFunc("/validate", processTimeout(validate, timeout))

	if err = http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	remote := os.Getenv("REMOTE_URL")
	scanOpts := types.ScanOptions{
		VulnType:            []string{"os", "library"},
		SecurityChecks:      []string{"vuln", "config"},
		ScanRemovedPackages: true,
		ListAllPackages:     true,
	}

	results := make([]externaldata.Item, 0)
	// iterate over all keys
	for _, image := range providerRequest.Request.Keys {
		log.Info("validate", "image", image, "remote", remote)
		s, cleanup, err := trivy.InitializeDockerScanner(ctx, image, client.CustomHeaders{}, client.RemoteURL(remote), timeout)
		if err != nil {
			results = append(results, externaldata.Item{
				Key:   image,
				Error: "unable to initialize scanner",
			})
			continue
		}
		defer cleanup()
		report, err := s.ScanArtifact(ctx, scanOpts)
		if err != nil {
			results = append(results, externaldata.Item{
				Key:   image,
				Error: "unable to scan image",
			})
			continue
		}

		if len(report.Results) > 0 {
			log.Info("validate", "vulnerabilities found", len(report.Results[0].Vulnerabilities))
			results = append(results, externaldata.Item{
				Key:   image,
				Value: len(report.Results[0].Vulnerabilities),
			})
		} else {
			log.Info("validate", "no vulnerabilities found", image)
			results = append(results, externaldata.Item{
				Key:   image,
				Value: 0,
			})
		}

	}
	sendResponse(&results, "", w)
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func processTimeout(h http.HandlerFunc, duration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()

		r = r.WithContext(ctx)

		processDone := make(chan bool)
		go func() {
			h(w, r)
			processDone <- true
		}()

		select {
		case <-ctx.Done():
			sendResponse(nil, "operation timed out", w)
		case <-processDone:
		}
	}
}
