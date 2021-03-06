package authorization

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
		Service:   "authorization",
		ShortCode: "limit-role-actions",
		Documentation: rule.RuleDocumentation{
			Summary:     "Roles limited to the required actions",
			Explanation: `The permissions granted to a role should be kept to the minimum required to be able to do the task. Wildcard permissions must not be used.`,
			Impact:      "Open permissions for subscriptions could result in an easily compromisable account",
			Resolution:  "Use targeted permissions for roles",
			BadExample: []string{`
data "azurerm_subscription" "primary" {
}

resource "azurerm_role_definition" "example" {
  name        = "my-custom-role"
  scope       = data.azurerm_subscription.primary.id
  description = "This is a custom role created via Terraform"

  permissions {
    actions     = ["*"]
    not_actions = []
  }

  assignable_scopes = [
    "/"
  ]
}
`},
			GoodExample: []string{`
data "azurerm_subscription" "primary" {
}

resource "azurerm_role_definition" "example" {
  name        = "my-custom-role"
  scope       = data.azurerm_subscription.primary.id
  description = "This is a custom role created via Terraform"

  permissions {
    actions     = ["*"]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.primary.id,
  ]
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_role_definition",
		},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if permissionBlock := resourceBlock.GetBlock("permissions"); permissionBlock.IsNotNil() {
				if actionsAttr := permissionBlock.GetAttribute("actions"); actionsAttr.IsNotNil() && actionsAttr.Contains("*") {
					// need more information
					if assignableScopesAttr := resourceBlock.GetAttribute("assignable_scopes"); assignableScopesAttr.IsNil() || assignableScopesAttr.Contains("/") {
						set.AddResult().
							WithDescription("Resource '%s' has wildcard action with open assignable_scopes", resourceBlock.FullName()).
							WithAttribute(actionsAttr)
					}
				}
			}
		},
	})
}
