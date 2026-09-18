package library

import (
	"context"

	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Detect scans language-specific packages and returns vulnerabilities.
func Detect(ctx context.Context, libType ftypes.LangType, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	// Pixi is a mixed ecosystem. Only genuine PyPI records use the Python
	// advisory driver; Conda names (even Python mappings) are not PyPI builds.
	if libType == ftypes.Pixi {
		var pythonPackages []ftypes.Package
		condaFound := false
		for _, pkg := range pkgs {
			if pkg.Identifier.PURL != nil && pkg.Identifier.PURL.Type == packageurl.TypePyPi {
				pythonPackages = append(pythonPackages, pkg)
			} else {
				condaFound = true
			}
		}
		if condaFound {
			log.WarnContext(ctx, "Pixi Conda packages are supported for SBOM and licenses, not vulnerability scanning")
		}
		libType, pkgs = ftypes.PythonPkg, pythonPackages
	}
	driver, ok := NewDriver(libType)
	if !ok {
		return nil, nil
	}

	vulns, err := detect(ctx, driver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
	}

	return vulns, nil
}

func detect(ctx context.Context, driver Driver, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	var vulnerabilities []types.DetectedVulnerability
	for _, pkg := range pkgs {
		if pkg.Version == "" {
			log.DebugContext(ctx, "Skipping vulnerability scan as no version is detected for the package",
				log.String("name", pkg.Name))
			continue
		}
		vulns, err := driver.DetectVulnerabilities(pkg.ID, pkg.Name, pkg.Version)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
		}

		for i := range vulns {
			vulns[i].Layer = pkg.Layer
			vulns[i].PkgPath = pkg.FilePath
			vulns[i].PkgIdentifier = pkg.Identifier
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}
