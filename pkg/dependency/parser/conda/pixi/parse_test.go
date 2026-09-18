package pixi

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/pixi.lock")
	require.NoError(t, err)
	return string(b)
}

func TestParse(t *testing.T) {
	for _, version := range []string{"6", "7"} {
		t.Run(version, func(t *testing.T) {
			data := strings.Replace(fixture(t), "version: 6", "version: "+version, 1)
			apps, err := Parse(t.Context(), "nested/pixi.lock", strings.NewReader(data))
			require.NoError(t, err)
			require.Len(t, apps, 3)
			assert.Equal(t, "nested/pixi.lock (default/linux-64)", apps[0].FilePath)
			require.Len(t, apps[0].Packages, 4)
			byName := map[string]int{}
			for i, pkg := range apps[0].Packages {
				byName[pkg.Name] = i
			}
			py := apps[0].Packages[byName["python"]]
			django := apps[0].Packages[byName["django"]]
			typing := apps[0].Packages[byName["typing-extensions"]]
			asgi := apps[0].Packages[byName["asgiref"]]
			assert.Equal(t, []string{typing.ID}, py.DependsOn)
			assert.ElementsMatch(t, []string{typing.ID, asgi.ID}, django.DependsOn)
			assert.Equal(t, []string{"Python-2.0"}, py.Licenses)
			assert.Equal(t, "sha256:"+strings.Repeat("a", 64), string(py.Digest))
			assert.Equal(t, "conda", py.Identifier.PURL.Type)
			assert.Equal(t, "pypi", django.Identifier.PURL.Type)
			assert.Contains(t, py.ID, "build=h123_0")
			assert.NotEqual(t, py.ID, apps[1].Packages[0].ID)
			assert.Equal(t, "4.2.3", apps[2].Packages[0].Version)
			again, err := Parse(t.Context(), "nested/pixi.lock", strings.NewReader(data))
			require.NoError(t, err)
			assert.Equal(t, apps, again)
		})
	}
}

func TestVersion5(t *testing.T) {
	data := `version: 5
 environments:
   default:
     packages:
       linux-64:
       - conda: https://example.org/linux-64/a-1.0-b.tar.bz2
 packages:
 - kind: conda
   url: https://example.org/linux-64/a-1.0-b.tar.bz2
   name: a
   version: '1.0'
   build: b
   subdir: linux-64
 `
	// Remove the indentation used to keep the raw literal legible.
	data = strings.ReplaceAll(data, "\n ", "\n")
	apps, err := Parse(t.Context(), "pixi.lock", strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, apps, 1)
	assert.Equal(t, "a", apps[0].Packages[0].Name)
}

func TestInvalid(t *testing.T) {
	for name, data := range map[string]string{
		"yaml": "[", "old": "version: 4", "future": "version: 8", "empty": "", "no environments": "version: 6",
		"multi document":   fixture(t) + "\n---\nversion: 6\n",
		"missing record":   strings.Replace(fixture(t), "- pypi: https://example.org/asgiref-3.8.1.whl\n  name:", "- pypi: https://example.org/other.whl\n  name:", 1),
		"both ecosystems":  strings.Replace(fixture(t), "  name: Django", "  conda: https://example.org/a.conda\n  name: Django", 1),
		"missing version":  strings.Replace(fixture(t), "  version: 4.2.0", "  version: ''", 1),
		"bad hash":         strings.Replace(fixture(t), strings.Repeat("a", 64), "not-a-hash", 1),
		"duplicate record": fixture(t) + "\n- pypi: https://example.org/unused.whl\n  name: unused\n  version: '1.0'\n",
	} {
		t.Run(name, func(t *testing.T) {
			apps, err := Parse(t.Context(), "pixi.lock", strings.NewReader(data))
			require.Error(t, err)
			assert.Nil(t, apps)
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Parse(ctx, "pixi.lock", strings.NewReader(fixture(t)))
	require.ErrorIs(t, err, context.Canceled)
}

func TestSourceRedactionAndMetadata(t *testing.T) {
	pkg, err := (record{reference: reference{PyPI: "https://user:password@example.org/a.whl?token=secret"}, Name: "Some_Package.Name", Version: "1.0", MD5: strings.Repeat("c", 32)}).packageInfo()
	require.NoError(t, err)
	assert.Equal(t, "some-package-name", pkg.Name)
	assert.NotContains(t, pkg.ID, "password")
	assert.NotContains(t, pkg.ID, "secret")
	assert.Equal(t, "md5:"+strings.Repeat("c", 32), string(pkg.Digest))
}

func FuzzParse(f *testing.F) {
	b, err := os.ReadFile("testdata/pixi.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(b))
	f.Add("version: 6\nenvironments: {}")
	f.Fuzz(func(t *testing.T, s string) { _, _ = Parse(t.Context(), "pixi.lock", strings.NewReader(s)) })
}

func TestUpstreamSnapshots(t *testing.T) {
	for _, file := range []string{"upstream-v5.lock", "upstream-v6.lock", "upstream-v7.lock"} {
		t.Run(file, func(t *testing.T) {
			f, err := os.Open("testdata/" + file)
			require.NoError(t, err)
			defer f.Close()
			apps, err := Parse(t.Context(), "pixi.lock", f)
			require.NoError(t, err)
			require.Len(t, apps, 1)
			require.Len(t, apps[0].Packages, 2)
			for _, pkg := range apps[0].Packages {
				assert.NotEmpty(t, pkg.Name)
				assert.NotEmpty(t, pkg.Version)
				assert.NotEmpty(t, pkg.Identifier.PURL)
				require.Len(t, pkg.Locations, 1)
				assert.Positive(t, pkg.Locations[0].StartLine)
			}
		})
	}
}

func TestEmptyAndAmbiguous(t *testing.T) {
	apps, err := Parse(t.Context(), "pixi.lock", strings.NewReader("version: 6\nenvironments: {}\npackages: []\n"))
	require.NoError(t, err)
	assert.Empty(t, apps)
	data := fixture(t)
	// Two builds of the same name cannot occupy the same environment/platform.
	data = strings.Replace(data, "      win-64:\n", "", 1)
	_, err = Parse(t.Context(), "pixi.lock", strings.NewReader(data))
	require.ErrorContains(t, err, "ambiguous package")
}

func TestDependencyRequirements(t *testing.T) {
	for _, tt := range []struct{ input, kind, want string }{
		{"conda-forge::lib-x >=1.0,<2", "conda", "lib-x"},
		{"typing_extensions[extra] >= 4", "pypi", "typing-extensions"},
		{"a @ https://example.org/a.whl", "pypi", "a"},
		{"__glibc >=2.17", "conda", "__glibc"},
	} {
		assert.Equal(t, tt.want, requirementName(tt.input, tt.kind))
	}
}

func TestLocalAndGitSources(t *testing.T) {
	for _, source := range []string{"../local", "file:///outside/project", "git+https://example.org/repo#deadbeef"} {
		pkg, err := (record{reference: reference{PyPI: source}, Name: "local", Version: "1.0"}).packageInfo()
		require.NoError(t, err)
		assert.Equal(t, source, pkg.Identifier.PURL.Qualifiers.Map()["download_url"])
	}
	_, err := (record{reference: reference{Conda: "https://example.org/not-an-archive"}}).packageInfo()
	require.Error(t, err)
	_, err = (record{reference: reference{PyPI: "https://example.org/%invalid"}, Name: "a", Version: "1"}).packageInfo()
	require.Error(t, err)
	_, err = (record{reference: reference{PyPI: "a"}, Name: "a", Version: "1", MD5: "bad"}).packageInfo()
	require.Error(t, err)
}

func TestAmbiguousPythonMappings(t *testing.T) {
	data := strings.Replace(fixture(t), "  license: Python-2.0", "  purls: [pkg:pypi/typing_extensions@4.12.0, 'not-a-purl', pkg:npm/other@1.0]\n  license: Python-2.0", 1)
	apps, err := Parse(t.Context(), "pixi.lock", strings.NewReader(data))
	require.NoError(t, err)
	for _, pkg := range apps[0].Packages {
		if pkg.Name == "django" {
			require.Len(t, pkg.DependsOn, 1)
			assert.Contains(t, pkg.DependsOn[0], "pkg:pypi/asgiref@")
		}
	}
	for range 10 {
		again, err := Parse(t.Context(), "pixi.lock", strings.NewReader(data))
		require.NoError(t, err)
		assert.Equal(t, apps, again)
	}
}
