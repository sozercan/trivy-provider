package appservice

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
		Provider:  provider.AzureProvider,
		Service:   "appservice",
		ShortCode: "use-secure-tls-policy",
		Documentation: rule.RuleDocumentation{
			Summary:     "Web App uses latest TLS version",
			Explanation: `Use a more recent TLS/SSL policy for the App Service`,
			Impact:      "The minimum TLS version for apps should be TLS1_2",
			Resolution:  "The TLS version being outdated and has known vulnerabilities",
			BadExample: []string{`
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
	  min_tls_version = "1.0"
  }
}
`},
			GoodExample: []string{`
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#min_tls_version",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_app_service",
		},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if resourceBlock.MissingChild("site_config") {
				return
			}

			if minTlsVersionAttr := resourceBlock.GetBlock("site_config").GetAttribute("min_tls_version"); minTlsVersionAttr.IsNotNil() && minTlsVersionAttr.NotEqual("1.2") {
				set.AddResult().
					WithDescription("Resource '%s' does not have site_config.min_tls_version set to 1.2", resourceBlock.FullName()).
					WithAttribute(minTlsVersionAttr)
			}
		},
	})
}
