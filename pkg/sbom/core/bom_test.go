package core_test

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

func TestEnsureBOMRefs(t *testing.T) {
	bom := core.NewBOM(core.Options{})
	root := &core.Component{Root: true, Name: "pixi.lock"}
	a := &core.Component{Name: "a", PkgIdentifier: types.PkgIdentifier{PURL: packageurl.NewPackageURL("pypi", "", "a", "1", nil, "")}}
	b := a.Clone()
	kept := &core.Component{Name: "kept", PkgIdentifier: types.PkgIdentifier{BOMRef: "existing"}}
	bom.AddComponent(root)
	bom.AddComponent(a)
	bom.AddComponent(b)
	bom.AddComponent(kept)
	bom.AddRelationship(a, b, core.RelationshipDependsOn)
	clone := bom.Clone()
	clone.EnsureBOMRefs()
	refs := map[string]bool{}
	for _, c := range clone.Components() {
		assert.NotEmpty(t, c.PkgIdentifier.BOMRef)
		assert.False(t, refs[c.PkgIdentifier.BOMRef])
		refs[c.PkgIdentifier.BOMRef] = true
	}
	assert.True(t, refs["existing"])
	assert.Empty(t, root.PkgIdentifier.BOMRef, "must not mutate the original BOM")
	assert.Equal(t, bom.Relationships(), clone.Relationships())
	before := clone.Clone()
	clone.EnsureBOMRefs()
	assert.Equal(t, before.Components(), clone.Components())
}
