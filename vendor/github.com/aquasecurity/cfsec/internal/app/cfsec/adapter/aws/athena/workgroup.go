package athena

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/athena"
)

func getWorkGroups(cfFile parser.FileContext) []athena.Workgroup {

	var workgroups []athena.Workgroup

	workgroupResources := cfFile.GetResourceByType("AWS::Athena::WorkGroup")

	for _, r := range workgroupResources {

		wg := athena.Workgroup{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("Name"),
			Encryption: athena.EncryptionConfiguration{
				Type: r.GetStringProperty("WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration.EncryptionOption"),
			},
			EnforceConfiguration: r.GetBoolProperty("WorkGroupConfiguration.EnforceWorkGroupConfiguration"),
		}

		workgroups = append(workgroups, wg)
	}

	return workgroups
}
