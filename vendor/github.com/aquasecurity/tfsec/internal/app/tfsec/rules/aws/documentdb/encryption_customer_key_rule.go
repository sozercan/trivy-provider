package documentdb

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

// generator-locked

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
		Provider:  provider.AWSProvider,
		Service:   "documentdb",
		ShortCode: "encryption-customer-key",
		Documentation: rule.RuleDocumentation{
			Summary:     "DocumentDB encryption should use Customer Managed Keys",
			Explanation: `Encryption using AWS keys provides protection for your DocumentDB underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
			Impact:      "Using AWS managed keys does not allow for fine grained control",
			Resolution:  "Enable encryption using customer managed keys",
			BadExample: []string{`
resource "aws_docdb_cluster" "docdb" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true
}
`},
			GoodExample: []string{`
resource "aws_kms_key" "docdb_encryption" {
	enable_key_rotation = true
}
			
resource "aws_docdb_cluster" "docdb" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true
  kms_key_id 			  = aws_kms_key.docdb_encryption.arn
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#kms_key_id",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_docdb_cluster",
			"aws_docdb_cluster_instance",
		},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			if resourceBlock.MissingChild("kms_key_id") {
				set.AddResult().
					WithDescription("Resource '%s' does not use CMK", resourceBlock.FullName())
				return
			}

			kmsKeyAttr := resourceBlock.GetAttribute("kms_key_id")
			if kmsKeyAttr.IsDataBlockReference() {
				kmsData, err := module.GetReferencedBlock(kmsKeyAttr)
				if err != nil {
					return
				}
				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr.IsNotNil() && keyIdAttr.StartsWith("alias/aws/") {
					set.AddResult().
						WithDescription("Resource '%s' explicitly uses the default CMK", resourceBlock.FullName()).
						WithAttribute(kmsKeyAttr)
				}
			}

		},
	})
}
