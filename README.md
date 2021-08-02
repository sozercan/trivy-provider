# trivy-provider

- Deploy Gatekeeper with external data enabled

- Deploy Trivy server using Helm chart: https://github.com/aquasecurity/trivy/tree/main/helm/trivy

- `kubectl apply -f manifest`
  - Update `REMOTE_URL` environment variable, if Trivy is not hosted in `http://trivy.default:4954`

- `kubectl apply -f policy/provider.yaml`
  - Update `proxyURL` if it's not `http://trivy-provider.default:8090`

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`
