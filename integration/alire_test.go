//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdxlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAlireSBOM(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.CopyFS(root, testutil.TxtarToFS(t,
		"../pkg/fanal/analyzer/language/ada/alire/testdata/diamond.txtar")))
	// A native language in the same artifact must retain its inventory/edges.
	require.NoError(t, os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{
  "name": "mixed_project", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "mixed_project", "version": "1.0.0", "dependencies": {"web_fixture": "1.0.0"}},
    "node_modules/web_fixture": {"version": "1.0.0", "license": "MIT", "dependencies": {"lodash": "4.17.21"}},
    "node_modules/lodash": {"version": "4.17.21", "license": "MIT"}
  }
}`), 0o600))
	before := alireSnapshot(t, root)
	wantVersions := map[string]string{
		"diamond_app": "1.0.0", "direct_dep": "1.0.0", "right_dep": "1.0.0", "leaf_dep": "2.0.0",
		"web_fixture": "1.0.0", "lodash": "4.17.21",
	}
	wantEdges := map[string][]string{
		"diamond_app": {"direct_dep", "right_dep"}, "direct_dep": {"leaf_dep"}, "right_dep": {"leaf_dep"},
		"web_fixture": {"lodash"},
	}
	for _, command := range []string{"fs", "repo"} {
		for _, format := range []string{"cyclonedx", "spdx-json"} {
			t.Run(command+"/"+format, func(t *testing.T) {
				output := filepath.Join(t.TempDir(), "sbom.json")
				require.NoError(t, execute([]string{command, "--format", format, "--output", output,
					"--skip-version-check", "--offline-scan", "--cache-dir", t.TempDir(), root}))
				versions, edges := alireSBOMGraph(t, output, format, true)
				assert.Equal(t, wantVersions, versions)
				assert.Equal(t, wantEdges, edges)
				// Both input formats must survive SBOM read/re-export and the native
				// JSON conversion path, which cannot rely on the in-memory BOM.
				native := filepath.Join(t.TempDir(), "native.json")
				require.NoError(t, execute([]string{"sbom", "--scanners", "license", "--format", "json",
					"--output", native, "--skip-version-check", "--cache-dir", t.TempDir(), output}))
				var report types.Report
				readAlireJSON(t, native, &report)
				roles := make(map[string]ftypes.Relationship)
				for _, result := range report.Results {
					if result.Type != ftypes.Alire {
						continue
					}
					for _, pkg := range result.Packages {
						roles[pkg.Name] = pkg.Relationship
					}
				}
				assert.Equal(t, map[string]ftypes.Relationship{
					"diamond_app": ftypes.RelationshipRoot, "direct_dep": ftypes.RelationshipDirect,
					"right_dep": ftypes.RelationshipDirect, "leaf_dep": ftypes.RelationshipIndirect,
				}, roles)
				for _, conversion := range []string{"sbom", "convert"} {
					reexport := filepath.Join(t.TempDir(), "reexport.json")
					args := []string{conversion, "--format", format, "--output", reexport}
					if conversion == "sbom" {
						args = append(args, "--scanners", "license", "--skip-version-check", "--cache-dir", t.TempDir(), output)
					} else {
						args = append(args, native)
					}
					require.NoError(t, execute(args))
					gotVersions, gotEdges := alireSBOMGraph(t, reexport, format, false)
					assert.Equal(t, wantVersions, gotVersions, conversion)
					assert.Equal(t, wantEdges, gotEdges, conversion)
				}
			})
		}
	}
	assert.Equal(t, before, alireSnapshot(t, root), "inventory must not mutate input files")

	t.Run("rootfs disabled", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "rootfs.json")
		require.NoError(t, execute([]string{"rootfs", "--format", "cyclonedx", "--output", output,
			"--skip-version-check", "--cache-dir", t.TempDir(), root}))
		versions, _ := alireSBOMGraph(t, output, "cyclonedx", false)
		assert.NotContains(t, versions, "diamond_app")
		assert.NotContains(t, versions, "leaf_dep")
	})
	t.Run("explicit vulnerability scan", func(t *testing.T) {
		cache := initDB(t)
		output := filepath.Join(t.TempDir(), "vuln.json")
		require.NoError(t, execute([]string{"fs", "--scanners", "vuln", "--format", "json", "--output", output,
			"--skip-version-check", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--cache-dir", cache, root}))
		var report types.Report
		readAlireJSON(t, output, &report)
		var alireResults int
		for _, result := range report.Results {
			if result.Type == ftypes.Alire {
				alireResults++
				assert.Len(t, result.Packages, 4)
				assert.Empty(t, result.Vulnerabilities)
			}
		}
		assert.Equal(t, 1, alireResults)
	})
}

func alireSBOMGraph(t *testing.T, file, format string, schema bool) (map[string]string, map[string][]string) {
	t.Helper()
	g := alireTestGraph{names: make(map[string]string), versions: make(map[string]string), refs: make(map[string]bool), edges: make(map[string][]string)}
	if format == "cyclonedx" {
		var bom cdx.BOM
		readAlireJSON(t, file, &bom)
		if schema {
			validateReport(t, bom.JSONSchema, bom)
		}
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			g.refs[bom.Metadata.Component.BOMRef] = true
		}
		if bom.Components != nil {
			for _, c := range *bom.Components {
				g.addPackage(t, c.BOMRef, c.Name, c.Version, c.PackageURL)
			}
		}
		if bom.Dependencies != nil {
			for _, dep := range *bom.Dependencies {
				assert.Contains(t, g.refs, dep.Ref)
				if dep.Dependencies != nil {
					for _, to := range *dep.Dependencies {
						g.addEdge(t, dep.Ref, to)
					}
				}
			}
		}
	} else {
		var doc spdx.Document
		readAlireJSON(t, file, &doc)
		require.NoError(t, spdxlib.ValidateDocument(&doc))
		if schema {
			validateReport(t, fmt.Sprintf(SPDXSchema, strings.TrimPrefix(doc.SPDXVersion, "SPDX-")), doc)
		}
		for _, pkg := range doc.Packages {
			var purl string
			for _, ref := range pkg.PackageExternalReferences {
				if ref.RefType == "purl" {
					purl = ref.Locator
				}
			}
			g.addPackage(t, string(pkg.PackageSPDXIdentifier), pkg.PackageName, pkg.PackageVersion, purl)
		}
		for _, rel := range doc.Relationships {
			if rel.Relationship == "DEPENDS_ON" {
				g.addEdge(t, string(rel.RefA.ElementRefID), string(rel.RefB.ElementRefID))
			}
		}
	}
	for _, targets := range g.edges {
		sort.Strings(targets)
	}
	return g.versions, g.edges
}

type alireTestGraph struct {
	names, versions map[string]string
	refs            map[string]bool
	edges           map[string][]string
}

func (g *alireTestGraph) addPackage(t *testing.T, ref, name, version, purl string) {
	assert.NotContains(t, g.refs, ref, "unique SBOM references")
	g.refs[ref] = true
	if purl == "" {
		return
	}
	parsed, err := packageurl.FromString(purl)
	require.NoError(t, err)
	if parsed.Type == "generic" {
		assert.Equal(t, "alire", parsed.Namespace)
		assert.NotEmpty(t, parsed.Qualifiers.Map()["alire_source"])
	}
	g.names[ref], g.versions[name] = name, version
}
func (g *alireTestGraph) addEdge(t *testing.T, from, to string) {
	assert.Contains(t, g.refs, from)
	assert.Contains(t, g.refs, to)
	if g.names[from] != "" && g.names[to] != "" {
		g.edges[g.names[from]] = append(g.edges[g.names[from]], g.names[to])
	}
}

func readAlireJSON(t *testing.T, path string, dst any) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, dst))
}

func alireSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		files[path] = string(data)
		return err
	}))
	return files
}
