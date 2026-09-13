package langpkg_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAlireInventoryWithoutVulnerabilityDriver(t *testing.T) {
	pkgs := ftypes.Packages{{ID: "ada_lib@1.0.0", Name: "ada_lib", Version: "1.0.0", Relationship: ftypes.RelationshipDirect}}
	for _, scanners := range []types.Scanners{nil, {types.VulnerabilityScanner}} {
		results, err := langpkg.NewScanner().Scan(t.Context(), types.ScanTarget{
			Applications: []ftypes.Application{{Type: ftypes.Alire, FilePath: "alire/alire.lock", Packages: pkgs}},
		}, types.ScanOptions{Scanners: scanners})
		require.NoError(t, err, "unsupported coverage must not require an advisory DB or fail detection")
		require.Len(t, results, 1)
		assert.Equal(t, []ftypes.Package(pkgs), results[0].Packages)
		assert.Equal(t, ftypes.Alire, results[0].Type)
		assert.Empty(t, results[0].Vulnerabilities)
	}
}
