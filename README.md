# trivy-provider

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

- Deploy Gatekeeper with external data enabled (`--enable-external-data`)

- Deploy Trivy server using Helm chart: https://github.com/aquasecurity/trivy/tree/main/helm/trivy

- `kubectl apply -f manifest`
  - Update `REMOTE_URL` environment variable, if Trivy is not hosted in `http://trivy.default:4954` (default)

- `kubectl apply -f policy/provider.yaml`
  - Update `proxyURL` if it's not `http://trivy-provider.default:8090` (default)

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`

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
