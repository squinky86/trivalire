package library_test

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestPixiVulnerabilities(t *testing.T) {
	_ = dbtest.InitDB(t, []string{"testdata/fixtures/pip.yaml", "testdata/fixtures/data-source.yaml"})
	defer db.Close()
	pkgs := []ftypes.Package{
		{ID: "pypi-vulnerable", Name: "django", Version: "4.2.0", Identifier: ftypes.PkgIdentifier{PURL: packageurl.NewPackageURL("pypi", "", "django", "4.2.0", nil, "")}},
		{ID: "pypi-fixed", Name: "django", Version: "4.2.3", Identifier: ftypes.PkgIdentifier{PURL: packageurl.NewPackageURL("pypi", "", "django", "4.2.3", nil, "")}},
		{ID: "conda", Name: "django", Version: "4.2.0", Identifier: ftypes.PkgIdentifier{PURL: packageurl.NewPackageURL("conda", "", "django", "4.2.0", nil, "")}},
		{ID: "unknown", Name: "django", Version: "4.2.0"},
	}
	vulns, err := library.Detect(t.Context(), ftypes.Pixi, pkgs)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-2023-36053", vulns[0].VulnerabilityID)
	assert.Equal(t, "pypi-vulnerable", vulns[0].PkgID)
}
