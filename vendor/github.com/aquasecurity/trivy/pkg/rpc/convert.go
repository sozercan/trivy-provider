package rpc

import (
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/protobuf/types/known/structpb"

	ftypes "github.com/aquasecurity/fanal/types"
	deptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/cache"
	"github.com/aquasecurity/trivy/rpc/common"
	"github.com/aquasecurity/trivy/rpc/scanner"
)

// ConvertToRPCPkgs returns the list of RPC package objects
func ConvertToRPCPkgs(pkgs []ftypes.Package) []*common.Package {
	var rpcPkgs []*common.Package
	for _, pkg := range pkgs {
		rpcPkgs = append(rpcPkgs, &common.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int32(pkg.Epoch),
			Arch:       pkg.Arch,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int32(pkg.SrcEpoch),
			License:    pkg.License,
			Layer:      ConvertToRPCLayer(pkg.Layer),
		})
	}
	return rpcPkgs
}

// ConvertFromRPCPkgs returns list of Fanal package objects
func ConvertFromRPCPkgs(rpcPkgs []*common.Package) []ftypes.Package {
	var pkgs []ftypes.Package
	for _, pkg := range rpcPkgs {
		pkgs = append(pkgs, ftypes.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int(pkg.Epoch),
			Arch:       pkg.Arch,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int(pkg.SrcEpoch),
			License:    pkg.License,
			Layer:      ConvertFromRPCLayer(pkg.Layer),
		})
	}
	return pkgs
}

// ConvertFromRPCLibraries returns list of Fanal library
func ConvertFromRPCLibraries(rpcLibs []*common.Library) []ftypes.Package {
	var pkgs []ftypes.Package
	for _, l := range rpcLibs {
		pkgs = append(pkgs, ftypes.Package{
			Name:    l.Name,
			Version: l.Version,
			License: l.License,
		})
	}
	return pkgs
}

// ConvertToRPCLibraries returns list of libraries
func ConvertToRPCLibraries(libs []deptypes.Library) []*common.Library {
	var rpcLibs []*common.Library
	for _, l := range libs {
		rpcLibs = append(rpcLibs, &common.Library{
			Name:    l.Name,
			Version: l.Version,
			License: l.License,
		})
	}
	return rpcLibs
}

// ConvertToRPCVulns returns common.Vulnerability
func ConvertToRPCVulns(vulns []types.DetectedVulnerability) []*common.Vulnerability {
	var rpcVulns []*common.Vulnerability
	for _, vuln := range vulns {
		severity, err := dbTypes.NewSeverity(vuln.Severity)
		if err != nil {
			log.Logger.Warn(err)
		}
		cvssMap := make(map[string]*common.CVSS) // This is needed because protobuf generates a map[string]*CVSS type
		for vendor, vendorSeverity := range vuln.CVSS {
			cvssMap[vendor] = &common.CVSS{
				V2Vector: vendorSeverity.V2Vector,
				V3Vector: vendorSeverity.V3Vector,
				V2Score:  vendorSeverity.V2Score,
				V3Score:  vendorSeverity.V3Score,
			}
		}

		var lastModifiedDate, publishedDate *timestamp.Timestamp
		if vuln.LastModifiedDate != nil {
			lastModifiedDate, _ = ptypes.TimestampProto(*vuln.LastModifiedDate) // nolint: errcheck
		}

		if vuln.PublishedDate != nil {
			publishedDate, _ = ptypes.TimestampProto(*vuln.PublishedDate) // nolint: errcheck
		}

		var customAdvisoryData, customVulnData *structpb.Value
		if vuln.Custom != nil {
			customAdvisoryData, _ = structpb.NewValue(vuln.Custom) // nolint: errcheck
		}
		if vuln.Vulnerability.Custom != nil {
			customVulnData, _ = structpb.NewValue(vuln.Vulnerability.Custom) // nolint: errcheck
		}

		rpcVulns = append(rpcVulns, &common.Vulnerability{
			VulnerabilityId:    vuln.VulnerabilityID,
			PkgName:            vuln.PkgName,
			InstalledVersion:   vuln.InstalledVersion,
			FixedVersion:       vuln.FixedVersion,
			Title:              vuln.Title,
			Description:        vuln.Description,
			Severity:           common.Severity(severity),
			References:         vuln.References,
			Layer:              ConvertToRPCLayer(vuln.Layer),
			Cvss:               cvssMap,
			SeveritySource:     vuln.SeveritySource,
			CweIds:             vuln.CweIDs,
			PrimaryUrl:         vuln.PrimaryURL,
			LastModifiedDate:   lastModifiedDate,
			PublishedDate:      publishedDate,
			CustomAdvisoryData: customAdvisoryData,
			CustomVulnData:     customVulnData,
		})
	}
	return rpcVulns
}

// ConvertToRPCMisconfs returns common.DetectedMisconfigurations
func ConvertToRPCMisconfs(misconfs []types.DetectedMisconfiguration) []*common.DetectedMisconfiguration {
	var rpcMisconfs []*common.DetectedMisconfiguration
	for _, m := range misconfs {
		severity, err := dbTypes.NewSeverity(m.Severity)
		if err != nil {
			log.Logger.Warn(err)
		}

		rpcMisconfs = append(rpcMisconfs, &common.DetectedMisconfiguration{
			Type:        m.Type,
			Id:          m.ID,
			Title:       m.Title,
			Description: m.Description,
			Message:     m.Message,
			Namespace:   m.Namespace,
			Resolution:  m.Resolution,
			Severity:    common.Severity(severity),
			PrimaryUrl:  m.PrimaryURL,
			References:  m.References,
			Status:      string(m.Status),
			Layer:       ConvertToRPCLayer(m.Layer),
		})
	}
	return rpcMisconfs
}

// ConvertToRPCLayer returns common.Layer
func ConvertToRPCLayer(layer ftypes.Layer) *common.Layer {
	return &common.Layer{
		Digest: layer.Digest,
		DiffId: layer.DiffID,
	}
}

// ConvertFromRPCResults converts scanner.Result to report.Result
func ConvertFromRPCResults(rpcResults []*scanner.Result) []report.Result {
	var results []report.Result
	for _, result := range rpcResults {
		results = append(results, report.Result{
			Target:            result.Target,
			Vulnerabilities:   ConvertFromRPCVulns(result.Vulnerabilities),
			Misconfigurations: ConvertFromRPCMisconfs(result.Misconfigurations),
			Class:             report.ResultClass(result.Class),
			Type:              result.Type,
			Packages:          ConvertFromRPCPkgs(result.Packages),
		})
	}
	return results
}

// ConvertFromRPCVulns converts []*common.Vulnerability to []types.DetectedVulnerability
func ConvertFromRPCVulns(rpcVulns []*common.Vulnerability) []types.DetectedVulnerability {
	var vulns []types.DetectedVulnerability
	for _, vuln := range rpcVulns {
		severity := dbTypes.Severity(vuln.Severity)
		cvssMap := make(dbTypes.VendorCVSS) // This is needed because protobuf generates a map[string]*CVSS type
		for vendor, vendorSeverity := range vuln.Cvss {
			cvssMap[vendor] = dbTypes.CVSS{
				V2Vector: vendorSeverity.V2Vector,
				V3Vector: vendorSeverity.V3Vector,
				V2Score:  vendorSeverity.V2Score,
				V3Score:  vendorSeverity.V3Score,
			}
		}

		var lastModifiedDate, publishedDate *time.Time
		if vuln.LastModifiedDate != nil {
			t, _ := ptypes.Timestamp(vuln.LastModifiedDate) // nolint: errcheck
			lastModifiedDate = &t
		}
		if vuln.PublishedDate != nil {
			t, _ := ptypes.Timestamp(vuln.PublishedDate) // nolint: errcheck
			publishedDate = &t
		}

		vulns = append(vulns, types.DetectedVulnerability{
			VulnerabilityID:  vuln.VulnerabilityId,
			PkgName:          vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			Vulnerability: dbTypes.Vulnerability{
				Title:            vuln.Title,
				Description:      vuln.Description,
				Severity:         severity.String(),
				CVSS:             cvssMap,
				References:       vuln.References,
				CweIDs:           vuln.CweIds,
				LastModifiedDate: lastModifiedDate,
				PublishedDate:    publishedDate,
				Custom:           vuln.CustomVulnData.AsInterface(),
			},
			Layer:          ConvertFromRPCLayer(vuln.Layer),
			SeveritySource: vuln.SeveritySource,
			PrimaryURL:     vuln.PrimaryUrl,
			Custom:         vuln.CustomAdvisoryData.AsInterface(),
		})
	}
	return vulns
}

// ConvertFromRPCMisconfs converts []*common.DetectedMisconfigurations to []types.DetectedMisconfiguration
func ConvertFromRPCMisconfs(rpcMisconfs []*common.DetectedMisconfiguration) []types.DetectedMisconfiguration {
	var misconfs []types.DetectedMisconfiguration
	for _, rpcMisconf := range rpcMisconfs {
		misconfs = append(misconfs, types.DetectedMisconfiguration{
			Type:        rpcMisconf.Type,
			ID:          rpcMisconf.Id,
			Title:       rpcMisconf.Title,
			Description: rpcMisconf.Description,
			Message:     rpcMisconf.Message,
			Namespace:   rpcMisconf.Namespace,
			Resolution:  rpcMisconf.Resolution,
			Severity:    rpcMisconf.Severity.String(),
			PrimaryURL:  rpcMisconf.PrimaryUrl,
			References:  rpcMisconf.References,
			Status:      types.MisconfStatus(rpcMisconf.Status),
			Layer:       ConvertFromRPCLayer(rpcMisconf.Layer),
		})
	}
	return misconfs
}

// ConvertFromRPCLayer converts *common.Layer to fanal.Layer
func ConvertFromRPCLayer(rpcLayer *common.Layer) ftypes.Layer {
	return ftypes.Layer{
		Digest: rpcLayer.Digest,
		DiffID: rpcLayer.DiffId,
	}
}

// ConvertFromRPCOS converts common.OS to fanal.OS
func ConvertFromRPCOS(rpcOS *common.OS) *ftypes.OS {
	if rpcOS == nil {
		return nil
	}
	return &ftypes.OS{
		Family: rpcOS.Family,
		Name:   rpcOS.Name,
		Eosl:   rpcOS.Eosl,
	}
}

// ConvertFromRPCPackageInfos converts common.PackageInfo to fanal.PackageInfo
func ConvertFromRPCPackageInfos(rpcPkgInfos []*common.PackageInfo) []ftypes.PackageInfo {
	var pkgInfos []ftypes.PackageInfo
	for _, rpcPkgInfo := range rpcPkgInfos {
		pkgInfos = append(pkgInfos, ftypes.PackageInfo{
			FilePath: rpcPkgInfo.FilePath,
			Packages: ConvertFromRPCPkgs(rpcPkgInfo.Packages),
		})
	}
	return pkgInfos
}

// ConvertFromRPCApplications converts common.Application to fanal.Application
func ConvertFromRPCApplications(rpcApps []*common.Application) []ftypes.Application {
	var apps []ftypes.Application
	for _, rpcApp := range rpcApps {
		apps = append(apps, ftypes.Application{
			Type:      rpcApp.Type,
			FilePath:  rpcApp.FilePath,
			Libraries: ConvertFromRPCLibraries(rpcApp.Libraries),
		})
	}
	return apps
}

// ConvertFromRPCMisconfigurations converts common.Misconfiguration to fanal.Misconfiguration
func ConvertFromRPCMisconfigurations(rpcMisconfs []*common.Misconfiguration) []ftypes.Misconfiguration {
	var misconfs []ftypes.Misconfiguration
	for _, rpcMisconf := range rpcMisconfs {
		misconfs = append(misconfs, ftypes.Misconfiguration{
			FileType:   rpcMisconf.FileType,
			FilePath:   rpcMisconf.FilePath,
			Successes:  ConvertFromRPCMisconfResults(rpcMisconf.Successes),
			Warnings:   ConvertFromRPCMisconfResults(rpcMisconf.Warnings),
			Failures:   ConvertFromRPCMisconfResults(rpcMisconf.Failures),
			Exceptions: ConvertFromRPCMisconfResults(rpcMisconf.Exceptions),
			Layer:      ftypes.Layer{},
		})
	}
	return misconfs
}

// ConvertFromRPCMisconfResults converts common.MisconfResult to fanal.MisconfResult
func ConvertFromRPCMisconfResults(rpcResults []*common.MisconfResult) []ftypes.MisconfResult {
	var results []ftypes.MisconfResult
	for _, r := range rpcResults {
		results = append(results, ftypes.MisconfResult{
			Namespace: r.Namespace,
			Message:   r.Message,
			PolicyMetadata: ftypes.PolicyMetadata{
				ID:       r.Id,
				Type:     r.Type,
				Title:    r.Title,
				Severity: r.Severity,
			},
		})
	}
	return results
}

// ConvertFromRPCPutArtifactRequest converts cache.PutArtifactRequest to fanal.PutArtifactRequest
func ConvertFromRPCPutArtifactRequest(req *cache.PutArtifactRequest) ftypes.ArtifactInfo {
	created, _ := ptypes.Timestamp(req.ArtifactInfo.Created) // nolint: errcheck
	return ftypes.ArtifactInfo{
		SchemaVersion:   int(req.ArtifactInfo.SchemaVersion),
		Architecture:    req.ArtifactInfo.Architecture,
		Created:         created,
		DockerVersion:   req.ArtifactInfo.DockerVersion,
		OS:              req.ArtifactInfo.Os,
		HistoryPackages: ConvertFromRPCPkgs(req.ArtifactInfo.HistoryPackages),
	}
}

// ConvertFromRPCPutBlobRequest returns ftypes.BlobInfo
func ConvertFromRPCPutBlobRequest(req *cache.PutBlobRequest) ftypes.BlobInfo {
	return ftypes.BlobInfo{
		SchemaVersion:     int(req.BlobInfo.SchemaVersion),
		Digest:            req.BlobInfo.Digest,
		DiffID:            req.BlobInfo.DiffId,
		OS:                ConvertFromRPCOS(req.BlobInfo.Os),
		PackageInfos:      ConvertFromRPCPackageInfos(req.BlobInfo.PackageInfos),
		Applications:      ConvertFromRPCApplications(req.BlobInfo.Applications),
		Misconfigurations: ConvertFromRPCMisconfigurations(req.BlobInfo.Misconfigurations),
		OpaqueDirs:        req.BlobInfo.OpaqueDirs,
		WhiteoutFiles:     req.BlobInfo.WhiteoutFiles,
	}
}

// ConvertToRPCOS returns common.OS
func ConvertToRPCOS(fos *ftypes.OS) *common.OS {
	if fos == nil {
		return nil
	}
	return &common.OS{
		Family: fos.Family,
		Name:   fos.Name,
		Eosl:   fos.Eosl,
	}
}

// ConvertToRPCArtifactInfo returns PutArtifactRequest
func ConvertToRPCArtifactInfo(imageID string, imageInfo ftypes.ArtifactInfo) *cache.PutArtifactRequest {
	t, err := ptypes.TimestampProto(imageInfo.Created)
	if err != nil {
		log.Logger.Warnf("invalid timestamp: %s", err)
	}

	return &cache.PutArtifactRequest{
		ArtifactId: imageID,
		ArtifactInfo: &cache.ArtifactInfo{
			SchemaVersion:   int32(imageInfo.SchemaVersion),
			Architecture:    imageInfo.Architecture,
			Created:         t,
			DockerVersion:   imageInfo.DockerVersion,
			Os:              imageInfo.OS,
			HistoryPackages: ConvertToRPCPkgs(imageInfo.HistoryPackages),
		},
	}
}

// ConvertToRPCBlobInfo returns PutBlobRequest
func ConvertToRPCBlobInfo(diffID string, blobInfo ftypes.BlobInfo) *cache.PutBlobRequest {
	var packageInfos []*common.PackageInfo
	for _, pkgInfo := range blobInfo.PackageInfos {
		packageInfos = append(packageInfos, &common.PackageInfo{
			FilePath: pkgInfo.FilePath,
			Packages: ConvertToRPCPkgs(pkgInfo.Packages),
		})
	}

	var applications []*common.Application
	for _, app := range blobInfo.Applications {
		var libs []*common.Library
		for _, lib := range app.Libraries {
			libs = append(libs, &common.Library{
				Name:    lib.Name,
				Version: lib.Version,
				License: lib.License,
			})
		}
		applications = append(applications, &common.Application{
			Type:      app.Type,
			FilePath:  app.FilePath,
			Libraries: libs,
		})
	}

	var misconfigurations []*common.Misconfiguration
	for _, m := range blobInfo.Misconfigurations {
		misconfigurations = append(misconfigurations, &common.Misconfiguration{
			FileType:   m.FileType,
			FilePath:   m.FilePath,
			Successes:  ConvertToMisconfResults(m.Successes),
			Warnings:   ConvertToMisconfResults(m.Warnings),
			Failures:   ConvertToMisconfResults(m.Failures),
			Exceptions: ConvertToMisconfResults(m.Exceptions),
		})

	}

	return &cache.PutBlobRequest{
		DiffId: diffID,
		BlobInfo: &cache.BlobInfo{
			SchemaVersion:     ftypes.BlobJSONSchemaVersion,
			Digest:            blobInfo.Digest,
			DiffId:            blobInfo.DiffID,
			Os:                ConvertToRPCOS(blobInfo.OS),
			PackageInfos:      packageInfos,
			Applications:      applications,
			Misconfigurations: misconfigurations,
			OpaqueDirs:        blobInfo.OpaqueDirs,
			WhiteoutFiles:     blobInfo.WhiteoutFiles,
		},
	}
}

// ConvertToMisconfResults returns common.MisconfResult
func ConvertToMisconfResults(results []ftypes.MisconfResult) []*common.MisconfResult {
	var rpcResults []*common.MisconfResult
	for _, r := range results {
		rpcResults = append(rpcResults, &common.MisconfResult{
			Namespace: r.Namespace,
			Message:   r.Message,
			Id:        r.ID,
			Type:      r.Type,
			Title:     r.Title,
			Severity:  r.Severity,
		})
	}
	return rpcResults
}

// ConvertToMissingBlobsRequest returns MissingBlobsRequest object
func ConvertToMissingBlobsRequest(imageID string, layerIDs []string) *cache.MissingBlobsRequest {
	return &cache.MissingBlobsRequest{
		ArtifactId: imageID,
		BlobIds:    layerIDs,
	}
}

// ConvertToRPCScanResponse converts report.Result to ScanResponse
func ConvertToRPCScanResponse(results report.Results, fos *ftypes.OS) *scanner.ScanResponse {
	var rpcResults []*scanner.Result
	for _, result := range results {
		rpcResults = append(rpcResults, &scanner.Result{
			Target:            result.Target,
			Class:             string(result.Class),
			Type:              result.Type,
			Vulnerabilities:   ConvertToRPCVulns(result.Vulnerabilities),
			Misconfigurations: ConvertToRPCMisconfs(result.Misconfigurations),
			Packages:          ConvertToRPCPkgs(result.Packages),
		})
	}

	return &scanner.ScanResponse{
		Os:      ConvertToRPCOS(fos),
		Results: rpcResults,
	}
}
