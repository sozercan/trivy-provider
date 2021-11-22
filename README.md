# trivy-provider

trivy-provider is used for validating whether images contain vulnerabilities using [trivy](https://github.com/aquasecurity/trivy).

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

- Deploy Gatekeeper with external data enabled (`--enable-external-data`)
```sh
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper  \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst
```

- Deploy Trivy server using Helm chart: https://github.com/aquasecurity/trivy/tree/main/helm/trivy
```sh
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm install trivy aquasecurity/trivy --namespace trivy --create-namespace
```

- `kubectl apply -f manifest`
  - > Update `REMOTE_URL` environment variable in the deployment, if Trivy service endpoint is not `http://trivy.trivy:4954` (default)

- `kubectl apply -f policy/provider.yaml`
  - > Update `url` if it's not `http://trivy-provider.trivy-provider:8090` (default)

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`

## Verification

- `kubectl apply -f policy/examples/vulnerable.yaml`
  - Request should be rejected
  ```
  Error from server ([vulnerable-image] Image alpine:3.10.0 contains 30 vulnerabilities
  [vulnerable-image] Image alpine:3.11.0 contains 22 vulnerabilities): error when creating "policy/examples/vulnerable.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [vulnerable-image] Image alpine:3.10.0 contains 30 vulnerabilities
  [vulnerable-image] Image alpine:3.11.0 contains 22 vulnerabilities
  ```

- `kubectl apply -f policy/examples/notvulnerable.yaml`
  - Request should be allowed
  ```
  deployment.apps/notvulnerable-deployment created
  ```
