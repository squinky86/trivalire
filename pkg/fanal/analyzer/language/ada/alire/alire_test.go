package alire

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestPostAnalyze(t *testing.T) {
	for _, tt := range []struct {
		fixture  string
		root     string
		versions map[string]string
		edges    map[string][]string
		warning  bool
	}{
		{"resolved", "inventory_app", map[string]string{"inventory_app": "1.0.0", "direct_dep": "1.0.0", "leaf_dep": "2.0.0"}, map[string][]string{"inventory_app": {"direct_dep"}, "direct_dep": {"leaf_dep"}}, false},
		{"diamond", "diamond_app", map[string]string{"diamond_app": "1.0.0", "direct_dep": "1.0.0", "right_dep": "1.0.0", "leaf_dep": "2.0.0"}, map[string][]string{"diamond_app": {"direct_dep", "right_dep"}, "direct_dep": {"leaf_dep"}, "right_dep": {"leaf_dep"}}, false},
		{"linked", "linked_app", map[string]string{"linked_app": "1.0.0", "direct_dep": "3.1.0", "leaf_dep": "2.0.0"}, map[string][]string{"linked_app": {"direct_dep"}, "direct_dep": {"leaf_dep"}}, false},
		{"version-pin", "pinned_app", map[string]string{"pinned_app": "1.0.0", "direct_dep": "1.0.0", "leaf_dep": "2.0.0"}, map[string][]string{"pinned_app": {"direct_dep"}, "direct_dep": {"leaf_dep"}}, false},
		{"empty", "empty_app", map[string]string{"empty_app": "1.0.0"}, make(map[string][]string), false},
		{"missed", "missing_app", map[string]string{"missing_app": "1.0.0"}, make(map[string][]string), true},
		{"unresolved", "unresolved_app", map[string]string{"unresolved_app": "1.0.0"}, make(map[string][]string), true},
	} {
		t.Run(tt.fixture, func(t *testing.T) {
			t.Parallel()
			files := fixture(t, tt.fixture)
			before := snapshot(files)
			result, warnings := analyze(t, files)
			require.Len(t, result.Applications, 1, warnings)
			app := result.Applications[0]
			assert.Equal(t, types.Alire, app.Type)
			versions, names, edges := make(map[string]string), make(map[string]string), make(map[string][]string)
			for _, pkg := range app.Packages {
				assert.NotContains(t, names, pkg.ID)
				versions[pkg.Name], names[pkg.ID] = pkg.Version, pkg.Name
				switch pkg.Name {
				case tt.root:
					assert.Equal(t, types.RelationshipRoot, pkg.Relationship)
				case "leaf_dep":
					assert.Equal(t, types.RelationshipIndirect, pkg.Relationship)
				default:
					assert.Equal(t, types.RelationshipDirect, pkg.Relationship)
				}
			}
			for _, pkg := range app.Packages {
				for _, dep := range pkg.DependsOn {
					require.Contains(t, names, dep)
					edges[pkg.Name] = append(edges[pkg.Name], names[dep])
				}
				sort.Strings(edges[pkg.Name])
			}
			assert.Equal(t, tt.versions, versions)
			assert.Equal(t, tt.edges, edges)
			if tt.warning {
				assert.Contains(t, warnings, "Incomplete ALIRE inventory")
			} else {
				assert.Empty(t, warnings)
			}
			again, _ := analyze(t, files)
			assert.Equal(t, result, again)
			assert.Equal(t, before, snapshot(files), "analysis must not mutate inputs")
		})
	}
}

func TestIncompleteEvidence(t *testing.T) {
	for _, tt := range []struct {
		name, fixture string
		change        func(fstest.MapFS)
		packages      int
	}{
		{"missing linked manifest", "linked", func(f fstest.MapFS) { delete(f, "local_dep/alire.toml") }, 1},
		{"missing root", "resolved", func(f fstest.MapFS) { delete(f, "resolved/alire.toml") }, 0},
		{"stale root constraint", "resolved", func(f fstest.MapFS) { replace(f, "resolved/alire.toml", "^1.0.0", "^9.0.0") }, 1},
		{"new direct dependency", "resolved", func(f fstest.MapFS) {
			f["resolved/alire.toml"].Data = append(f["resolved/alire.toml"].Data, []byte("new_dep = \"*\"\n")...)
		}, 1},
		{"removed dependency", "resolved", func(f fstest.MapFS) { replace(f, "resolved/alire.toml", `direct_dep = "^1.0.0"`, "") }, 1},
		{"changed linked name", "linked", func(f fstest.MapFS) { replace(f, "local_dep/alire.toml", `name = "direct_dep"`, `name = "wrong_dep"`) }, 2},
		{"changed linked dependencies", "linked", func(f fstest.MapFS) { replace(f, "local_dep/alire.toml", `leaf_dep = "^2.0.0"`, `new_dep = "*"`) }, 2},
		{"removed version pin", "version-pin", func(f fstest.MapFS) { replace(f, "version-pin/alire.toml", `direct_dep = { version = "1.0.0" }`, "") }, 1},
		{"remote pin", "linked", func(f fstest.MapFS) {
			replace(f, "linked/alire.toml", `path = "../local_dep"`, `url = "https://example.invalid/repo.git"`)
		}, 2},
		{"malformed lock", "resolved", func(f fstest.MapFS) { f["resolved/alire/alire.lock"].Data = []byte("[") }, 1},
		{"conditional dependencies", "resolved", func(f fstest.MapFS) {
			replace(f, "resolved/alire/alire.lock", `leaf_dep = "^2.0.0"`, `"case(os)" = { linux = { leaf_dep = "^2.0.0" } }`)
		}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			files := fixture(t, tt.fixture)
			tt.change(files)
			result, warnings := analyze(t, files)
			assert.Contains(t, warnings, "Incomplete ALIRE inventory")
			var packages types.Packages
			for _, app := range result.Applications {
				packages = append(packages, app.Packages...)
			}
			assert.Len(t, packages, tt.packages, warnings)
			for _, pkg := range packages {
				assert.Equal(t, types.RelationshipRoot, pkg.Relationship)
				assert.Empty(t, pkg.DependsOn)
			}
		})
	}
}

func TestProjectPairing(t *testing.T) {
	files := fixture(t, "resolved")
	for name, file := range fixture(t, "resolved") {
		files["nested/"+name] = file
	}
	replace(files, "nested/resolved/alire/alire.lock", "sources/direct_dep", "private-index/direct_dep")
	// Generated copies must not create extra projects.
	files["resolved/alire/cache/copied/alire.toml"] = files["resolved/alire.toml"]
	files["resolved/alire/cache/copied/alire/alire.lock"] = files["resolved/alire/alire.lock"]
	result, warnings := analyze(t, files)
	require.Empty(t, warnings)
	require.Len(t, result.Applications, 2)
	first, second := result.Applications[0], result.Applications[1]
	assert.NotEqual(t, first.Packages[0].ID, second.Packages[0].ID, "root locations distinguish identities")
	assert.NotEqual(t, first.Packages[1].ID, second.Packages[1].ID, "different release sources distinguish identities")
	delete(files, "nested/resolved/alire.toml")
	result, warnings = analyze(t, files)
	assert.Len(t, result.Applications, 1, "never borrow another project's root")
	assert.Contains(t, warnings, "manifest is unavailable")
}

func TestScanBoundary(t *testing.T) {
	for _, link := range []string{"../../outside", "/outside", `C:\outside`, `\\host\share`, "../alire/cache/dep"} {
		t.Run(link, func(t *testing.T) {
			files := fixture(t, "linked")
			delete(files, "local_dep/alire.toml")
			replace(files, "linked/alire/alire.lock", "../local_dep", strings.ReplaceAll(link, `\`, `\\`))
			result, warnings := analyze(t, files)
			require.Len(t, result.Applications, 1)
			assert.Len(t, result.Applications[0].Packages, 1)
			assert.Contains(t, warnings, "Incomplete ALIRE inventory")
		})
	}
	// A normal symlink fixture is sufficient to verify exclusion; no host data
	// outside these disposable test directories is read.
	root, outside := t.TempDir(), t.TempDir()
	for name, f := range fixture(t, "linked") {
		if name == "local_dep/alire.toml" {
			require.NoError(t, os.WriteFile(filepath.Join(outside, "alire.toml"), f.Data, 0o600))
			continue
		}
		dst := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o700))
		require.NoError(t, os.WriteFile(dst, f.Data, 0o600))
	}
	if err := os.Symlink(outside, filepath.Join(root, "local_dep")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result, warnings := analyze(t, os.DirFS(root))
	require.Len(t, result.Applications, 1)
	assert.Len(t, result.Applications[0].Packages, 1)
	assert.Contains(t, warnings, "manifest is unavailable")
}

func TestProjectDirectoryNamedAlire(t *testing.T) {
	files := fstest.MapFS{}
	for name, file := range fixture(t, "resolved") {
		files["alire/"+name] = file
	}
	result, warnings := analyze(t, files)
	require.Empty(t, warnings)
	require.Len(t, result.Applications, 1)
	assert.Equal(t, "alire/resolved/alire/alire.lock", result.Applications[0].FilePath)
	assert.Len(t, result.Applications[0].Packages, 3)
}

func TestActionsAreMetadata(t *testing.T) {
	files := fixture(t, "resolved")
	files["resolved/alire.toml"].Data = append(files["resolved/alire.toml"].Data, []byte(`
[[actions]]
type = "post-fetch"
command = ["trivy-alire-fixture-command-must-not-run"]
`)...)
	before := snapshot(files)
	result, warnings := analyze(t, files)
	require.Empty(t, warnings)
	require.Len(t, result.Applications, 1)
	assert.Len(t, result.Applications[0].Packages, 3)
	assert.Equal(t, before, snapshot(files))
}

func TestRequired(t *testing.T) {
	a := &alireAnalyzer{}
	for _, name := range []string{"alire.toml", "alire/alire.lock", "project/alire.toml", `project\alire\alire.lock`} {
		if strings.Contains(name, `\`) && filepath.Separator != '\\' {
			continue // filepath.ToSlash interprets native OS separators
		}
		assert.True(t, a.Required(name, nil), name)
	}
	for _, name := range []string{"alire.lock", "alire.loc", "alire/alire.loc", "alire/cache/crate/alire.toml", "alire/cache/crate/alire/alire.lock", "other.txt"} {
		assert.False(t, a.Required(name, nil), name)
	}
	assert.Contains(t, analyzer.TypeLanguages, analyzer.TypeAlire)
	assert.Contains(t, analyzer.TypeLockfiles, analyzer.TypeAlire, "disabled for image and rootfs commands")
}

func fixture(t *testing.T, name string) fstest.MapFS {
	t.Helper()
	src := testutil.TxtarToFS(t, "testdata/"+name+".txtar")
	files := fstest.MapFS{}
	require.NoError(t, fs.WalkDir(src, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(src, name)
		files[name] = &fstest.MapFile{Data: data}
		return err
	}))
	return files
}

func analyze(t *testing.T, files fs.FS) (*analyzer.AnalysisResult, string) {
	t.Helper()
	var warnings bytes.Buffer
	a := &alireAnalyzer{logger: log.New(log.NewHandler(&warnings, nil))}
	result, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{FS: files})
	require.NoError(t, err)
	return result, warnings.String()
}

func replace(files fstest.MapFS, name, old, replacement string) {
	files[name].Data = []byte(strings.ReplaceAll(string(files[name].Data), old, replacement))
}

func snapshot(files fstest.MapFS) map[string]string {
	result := make(map[string]string)
	for name, f := range files {
		result[name] = string(f.Data)
	}
	return result
}
