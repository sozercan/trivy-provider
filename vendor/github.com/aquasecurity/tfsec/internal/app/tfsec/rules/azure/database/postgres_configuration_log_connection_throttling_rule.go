package database

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.AzureProvider,
		Service:   "database",
		ShortCode: "postgres-configuration-log-connection-throttling",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server",
			Explanation: `Postgresql can generate logs for connection throttling to improve visibility for audit and configuration issue resolution.`,
			Impact:      "No log information to help diagnosing connection contention issues",
			Resolution:  "Enable connection throttling logging",
			BadExample: []string{`
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  sku_name   = "GP_Gen5_4"
  version    = "9.6"
  storage_mb = 640000
}
`},
			GoodExample: []string{`
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_postgresql_server" "example" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  sku_name   = "GP_Gen5_4"
  version    = "9.6"
  storage_mb = 640000
}

resource "azurerm_postgresql_configuration" "example" {
	name                = "connection_throttling"
	resource_group_name = azurerm_resource_group.example.name
	server_name         = azurerm_postgresql_server.example.name
	value               = "on"
  }
  
  `},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration",
				"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_postgresql_server",
		},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			referencingBlocks, err := module.GetReferencingResources(resourceBlock, "azurerm_postgresql_configuration", "server_name")
			if err != nil {
				debug.Log("error occurred trying to get the referencing block for %s", resourceBlock.FullName())
			}
			for _, refBlock := range referencingBlocks {
				if nameAttr := refBlock.GetAttribute("name"); nameAttr.IsNotNil() && nameAttr.Equals("connection_throttling") {
					if valAttr := refBlock.GetAttribute("value"); valAttr.IsNotNil() && valAttr.Equals("on", block.IgnoreCase) {
						return
					}
				}
			}
			set.AddResult().
				WithDescription("Resource '%s' does not have a corresponding log configuration enabling 'connection_throttling'", resourceBlock.FullName())
		},
	})
}
