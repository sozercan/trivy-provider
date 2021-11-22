package gke

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.GoogleProvider,
		Service:   "gke",
		ShortCode: "enable-network-policy",
		Documentation: rule.RuleDocumentation{
			Summary:     "Network Policy should be enabled on GKE clusters",
			Explanation: `Enabling a network policy allows the segregation of network traffic by namespace`,
			Impact:      "Unrestricted inter-cluster communication",
			Resolution:  "Enable network policy",
			BadExample: []string{`
resource "google_service_account" "default" {
  account_id   = "service-account-id"
  display_name = "Service Account"
}

resource "google_container_cluster" "bad_example" {
  name     = "my-gke-cluster"
  location = "us-central1"

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
  network_policy {
    enabled = false
  }
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  name       = "my-node-pool"
  location   = "us-central1"
  cluster    = google_container_cluster.primary.name
  node_count = 1

  node_config {
    preemptible  = true
    machine_type = "e2-medium"

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.default.email
    oauth_scopes    = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
`},
			GoodExample: []string{`
resource "google_service_account" "default" {
  account_id   = "service-account-id"
  display_name = "Service Account"
}

resource "google_container_cluster" "good_example" {
  name     = "my-gke-cluster"
  location = "us-central1"

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
  network_policy {
    enabled = true
  }
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  name       = "my-node-pool"
  location   = "us-central1"
  cluster    = google_container_cluster.primary.name
  node_count = 1

  node_config {
    preemptible  = true
    machine_type = "e2-medium"

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.default.email
    oauth_scopes    = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enabled",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"google_container_cluster",
		},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
			if enabledAttr := resourceBlock.GetBlock("network_policy").GetAttribute("enabled"); enabledAttr.IsNil() { // alert on use of default value
				set.AddResult().
					WithDescription("Resource '%s' uses default value for network_policy.enabled", resourceBlock.FullName())
			} else if enabledAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' does not have network_policy.enabled set to true", resourceBlock.FullName()).
					WithAttribute(enabledAttr)
			}
		},
	})
}
