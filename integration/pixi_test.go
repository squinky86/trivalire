//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdxlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Exercise the public commands, including re-import and JSON conversion, without
// requiring a vulnerability database, a package manager, or network access.
func TestPixiSBOM(t *testing.T) {
	root := t.TempDir()
	lock, err := os.ReadFile("../pkg/dependency/parser/conda/pixi/testdata/pixi.lock")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "pixi.lock"), lock, 0o600))
	for _, command := range []string{"fs", "repo"} {
		for _, format := range []string{"cyclonedx", "spdx-json"} {
			t.Run(command+"/"+format, func(t *testing.T) {
				output := filepath.Join(t.TempDir(), "sbom.json")
				require.NoError(t, execute([]string{command, "--format", format, "--output", output, "--offline-scan", "--skip-version-check", "--cache-dir", t.TempDir(), root}))
				pkgs, edges := pixiGraph(t, output, format)
				require.Len(t, pkgs, 6)  // two Python builds, two Django versions, asgiref, typing-extensions
				require.Len(t, edges, 3) // python -> typing, django -> asgiref and typing
				native := filepath.Join(t.TempDir(), "report.json")
				require.NoError(t, execute([]string{"sbom", "--scanners", "license", "--format", "json", "--output", native, "--skip-version-check", "--cache-dir", t.TempDir(), output}))
				for _, conversion := range []string{"sbom", "convert"} {
					for _, toFormat := range []string{"cyclonedx", "spdx-json"} {
						converted := filepath.Join(t.TempDir(), "converted.json")
						args := []string{conversion, "--format", toFormat, "--output", converted}
						if conversion == "sbom" {
							args = append(args, "--scanners", "license", "--skip-version-check", "--cache-dir", t.TempDir(), output)
						} else {
							args = append(args, native)
						}
						require.NoError(t, execute(args))
						gotPkgs, gotEdges := pixiGraph(t, converted, toFormat)
						assert.Equal(t, pkgs, gotPkgs, conversion+"/"+toFormat)
						assert.Equal(t, edges, gotEdges, conversion+"/"+toFormat)
					}
				}
			})
		}
	}
	t.Run("rootfs excludes lockfiles", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "rootfs.json")
		require.NoError(t, execute([]string{"rootfs", "--format", "cyclonedx", "--output", output, "--skip-version-check", "--cache-dir", t.TempDir(), root}))
		pkgs, _ := pixiGraph(t, output, "cyclonedx")
		assert.Empty(t, pkgs)
	})
	t.Run("license scan", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "licenses.json")
		require.NoError(t, execute([]string{"fs", "--scanners", "license", "--format", "json", "--list-all-pkgs", "--output", output, "--skip-version-check", "--cache-dir", t.TempDir(), root}))
		report := readReport(t, output)
		var count int
		for _, result := range report.Results {
			count += len(result.Licenses)
		}
		assert.Equal(t, 5, count)
	})
	after, err := os.ReadFile(filepath.Join(root, "pixi.lock"))
	require.NoError(t, err)
	assert.Equal(t, lock, after)
}

type pixiInventory struct {
	Name, Version    string
	Licenses, Hashes []string
}

func pixiGraph(t *testing.T, filename, format string) (map[string]pixiInventory, []string) {
	t.Helper()
	data, err := os.ReadFile(filename)
	require.NoError(t, err)
	pkgs := map[string]pixiInventory{}
	refs := map[string]string{}
	var pairs [][2]string
	add := func(ref, purl, name, version string, licenses, hashes []string) {
		if purl == "" {
			return
		}
		parsed, err := packageurl.FromString(purl)
		require.NoError(t, err)
		assert.Contains(t, []string{"conda", "pypi"}, parsed.Type)
		slices.Sort(licenses)
		slices.Sort(hashes)
		refs[ref] = purl
		pkgs[purl] = pixiInventory{name, version, licenses, hashes}
	}
	if format == "cyclonedx" {
		var bom cdx.BOM
		require.NoError(t, json.Unmarshal(data, &bom))
		if bom.Components != nil {
			for _, c := range *bom.Components {
				var licenses, hashes []string
				if c.Licenses != nil {
					for _, l := range *c.Licenses {
						if l.Expression != "" {
							licenses = append(licenses, l.Expression)
						} else if l.License != nil {
							if l.License.ID != "" {
								licenses = append(licenses, l.License.ID)
							} else {
								licenses = append(licenses, l.License.Name)
							}
						}
					}
				}
				if c.Hashes != nil {
					for _, h := range *c.Hashes {
						hashes = append(hashes, h.Value)
					}
				}
				add(c.BOMRef, c.PackageURL, c.Name, c.Version, licenses, hashes)
			}
		}
		if bom.Dependencies != nil {
			for _, d := range *bom.Dependencies {
				if d.Dependencies != nil {
					for _, to := range *d.Dependencies {
						pairs = append(pairs, [2]string{d.Ref, to})
					}
				}
			}
		}
	} else {
		var doc spdx.Document
		require.NoError(t, json.Unmarshal(data, &doc))
		require.NoError(t, spdxlib.ValidateDocument(&doc))
		for _, p := range doc.Packages {
			var pu string
			for _, ref := range p.PackageExternalReferences {
				if ref.RefType == "purl" {
					pu = ref.Locator
				}
			}
			var licenses, hashes []string
			if p.PackageLicenseDeclared != "" && p.PackageLicenseDeclared != "NOASSERTION" {
				licenses = append(licenses, p.PackageLicenseDeclared)
			}
			for _, h := range p.PackageChecksums {
				hashes = append(hashes, h.Value)
			}
			add(string(p.PackageSPDXIdentifier), pu, p.PackageName, p.PackageVersion, licenses, hashes)
		}
		for _, r := range doc.Relationships {
			if r.Relationship == "DEPENDS_ON" {
				pairs = append(pairs, [2]string{string(r.RefA.ElementRefID), string(r.RefB.ElementRefID)})
			}
		}
	}
	var edges []string
	for _, p := range pairs {
		if refs[p[0]] != "" && refs[p[1]] != "" {
			edges = append(edges, refs[p[0]]+" -> "+refs[p[1]])
		}
	}
	slices.Sort(edges)
	edges = slices.Compact(edges)
	return pkgs, edges
}

func TestPixiVulnerabilityReports(t *testing.T) {
	root := t.TempDir()
	lock, err := os.ReadFile("../pkg/dependency/parser/conda/pixi/testdata/pixi.lock")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "pixi.lock"), lock, 0o600))
	cache := dbtest.InitDB(t, []string{"../pkg/detector/library/testdata/fixtures/pip.yaml", "../pkg/detector/library/testdata/fixtures/data-source.yaml", "testdata/fixtures/pixi/vulnerability.yaml"})
	require.NoError(t, metadata.NewClient(db.Dir(cache)).Update(metadata.Metadata{Version: db.SchemaVersion, NextUpdate: time.Now().Add(24 * time.Hour), UpdatedAt: time.Now(), DownloadedAt: time.Now()}))
	require.NoError(t, dbtest.Close())
	common := []string{"--scanners", "vuln", "--skip-db-update", "--skip-version-check", "--offline-scan", "--cache-dir", cache}
	for _, format := range []string{"json", "table", "sarif", "cyclonedx", "spdx-json"} {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "report")
			args := append([]string{"fs", "--format", format, "--output", output}, common...)
			args = append(args, root)
			require.NoError(t, execute(args))
			data, err := os.ReadFile(output)
			require.NoError(t, err)
			if format != "spdx-json" {
				assert.Contains(t, string(data), "CVE-2023-36053")
			}
			if format == "json" {
				report := readReport(t, output)
				var ids []string
				for _, r := range report.Results {
					for _, v := range r.Vulnerabilities {
						ids = append(ids, v.VulnerabilityID)
						assert.Equal(t, "pypi", v.PkgIdentifier.PURL.Type)
					}
				}
				assert.Equal(t, []string{"CVE-2023-36053"}, ids)
			}
			if format == "cyclonedx" || format == "spdx-json" {
				rescanned := filepath.Join(t.TempDir(), "rescanned.cdx.json")
				args = append([]string{"sbom", "--format", "cyclonedx", "--output", rescanned}, common...)
				args = append(args, output)
				require.NoError(t, execute(args))
				data, err = os.ReadFile(rescanned)
				require.NoError(t, err)
				var bom cdx.BOM
				require.NoError(t, json.Unmarshal(data, &bom))
				require.NotNil(t, bom.Vulnerabilities)
				require.Len(t, *bom.Vulnerabilities, 1)
				v := (*bom.Vulnerabilities)[0]
				assert.Equal(t, "CVE-2023-36053", v.ID)
				require.NotNil(t, v.Affects)
				require.Len(t, *v.Affects, 1)
				var matched bool
				for _, c := range *bom.Components {
					if c.BOMRef == (*v.Affects)[0].Ref {
						matched = true
						assert.Equal(t, "django", c.Name)
						assert.Equal(t, "4.2.0", c.Version)
					}
				}
				assert.True(t, matched, "finding must reference the vulnerable component")
			}
		})
	}
	t.Run("exit code", func(t *testing.T) {
		// The CLI returns its requested exit status as an error for callers.
		args := append([]string{"fs", "--exit-code", "17", "--format", "json", "--output", filepath.Join(t.TempDir(), "report")}, common...)
		args = append(args, root)
		err := execute(args)
		var exitErr *types.ExitError
		require.ErrorAs(t, err, &exitErr)
		assert.Equal(t, 17, exitErr.Code)
	})
	for _, filter := range []string{"severity", "ignore"} {
		t.Run(filter, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "filtered.json")
			args := append([]string{"fs", "--format", "json", "--output", output}, common...)
			if filter == "severity" {
				args = append(args, "--severity", "CRITICAL")
			} else {
				ignore := filepath.Join(t.TempDir(), ".trivyignore")
				require.NoError(t, os.WriteFile(ignore, []byte("CVE-2023-36053\n"), 0o600))
				args = append(args, "--ignorefile", ignore)
			}
			args = append(args, root)
			require.NoError(t, execute(args))
			for _, result := range readReport(t, output).Results {
				assert.Empty(t, result.Vulnerabilities)
			}
		})
	}

}

func TestPixiDiscovery(t *testing.T) {
	root := t.TempDir()
	lock, err := os.ReadFile("../pkg/dependency/parser/conda/pixi/testdata/pixi.lock")
	require.NoError(t, err)
	for _, name := range []string{"pixi.lock", "nested/pixi.lock"} {
		file := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o700))
		require.NoError(t, os.WriteFile(file, lock, 0o600))
	}
	// Installed environments must continue to work with existing analyzers even
	// when development lockfiles are disabled for rootfs/image scans.
	for name, content := range map[string]string{
		".pixi/envs/default/conda-meta/native-lib-1.0-0.json":                               `{"name":"native-lib","version":"1.0","license":"MIT"}`,
		".pixi/envs/default/lib/python3.12/site-packages/python_lib-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: python-lib\nVersion: 1.0\nLicense: MIT\n",
	} {
		file := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o700))
		require.NoError(t, os.WriteFile(file, []byte(content), 0o600))
	}
	for _, tt := range []struct {
		name, command           string
		flags                   []string
		wantPixi, wantInstalled int
	}{
		{name: "nested", command: "fs", wantPixi: 6},
		{name: "skip nested", command: "fs", flags: []string{"--skip-dirs", "nested"}, wantPixi: 3},
		{name: "rootfs installed", command: "rootfs", wantInstalled: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "report.json")
			args := []string{tt.command, "--scanners", "license", "--format", "json", "--list-all-pkgs", "--output", output, "--skip-version-check", "--cache-dir", t.TempDir()}
			args = append(args, tt.flags...)
			args = append(args, root)
			require.NoError(t, execute(args))
			report := readReport(t, output)
			var pixi, installed int
			for _, r := range report.Results {
				if r.Type == "pixi" {
					pixi++
				}
				if r.Type == "conda-pkg" || r.Type == "python-pkg" {
					installed += len(r.Packages)
				}
			}
			assert.Equal(t, tt.wantPixi, pixi)
			assert.Equal(t, tt.wantInstalled, installed)
		})
	}
}
