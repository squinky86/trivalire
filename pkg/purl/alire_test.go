package purl_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAlirePackageURL(t *testing.T) {
	p, err := purl.New(ftypes.Alire, types.Metadata{}, ftypes.Package{Name: "ada_lib", Version: "1.2.3+build.1"})
	require.NoError(t, err)
	assert.Equal(t, "pkg:generic/alire/ada_lib@1.2.3%2Bbuild.1", p.String())
	assert.Equal(t, ftypes.Alire, p.LangType())
	assert.Equal(t, types.ClassLangPkg, p.Class())
	pkg := p.Package()
	assert.Equal(t, "ada_lib", pkg.Name)
	assert.Equal(t, "1.2.3+build.1", pkg.Version)
	assert.Equal(t, p.String(), pkg.ID)

	for _, text := range []string{
		"pkg:generic/alire/ada_lib@1.2.3%2Bbuild.1?alire_source=abc&download_url=https%3A%2F%2Fexample.invalid%2Fa%20b.tar.gz",
		"pkg:generic/alire/ada_lib@1.2.3?alire_source=def",
	} {
		p, err := purl.FromString(text)
		require.NoError(t, err)
		pkg := p.Package()
		data, err := json.Marshal(pkg)
		require.NoError(t, err)
		var decoded ftypes.Package
		require.NoError(t, json.Unmarshal(data, &decoded))
		canonical := strings.ReplaceAll(text, "https%3A", "https:")
		assert.Equal(t, canonical, decoded.Identifier.PURL.String())
		assert.Equal(t, canonical, decoded.ID, "native JSON retains source-aware identity")
	}
	for _, text := range []string{"pkg:generic/ada_lib@1.0.0", "pkg:generic/other/ada_lib@1.0.0", "pkg:generic/alire/other/ada_lib@1.0.0"} {
		p, err := purl.FromString(text)
		require.NoError(t, err)
		assert.Equal(t, ftypes.LangType(purl.TypeUnknown), p.LangType())
		assert.Equal(t, types.ClassUnknown, p.Class())
	}
	p, err = purl.FromString("pkg:cargo/ada_lib@1.0.0")
	require.NoError(t, err)
	assert.Equal(t, ftypes.Cargo, p.LangType(), "ALIRE is never mapped to crates.io")
}
