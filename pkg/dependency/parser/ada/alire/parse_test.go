package alire

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	for _, tt := range []struct {
		file     string
		versions map[string]string
		edges    map[string][]string
	}{
		{"resolved", map[string]string{"direct_dep": "1.0.0", "leaf_dep": "2.0.0"}, map[string][]string{"direct_dep": {"leaf_dep"}}},
		{"diamond", map[string]string{"direct_dep": "1.0.0", "right_dep": "1.0.0", "leaf_dep": "2.0.0"}, map[string][]string{"direct_dep": {"leaf_dep"}, "right_dep": {"leaf_dep"}}},
		{"version-pin", map[string]string{"direct_dep": "1.0.0", "leaf_dep": "2.0.0"}, map[string][]string{"direct_dep": {"leaf_dep"}}},
		{"empty", make(map[string]string), make(map[string][]string)},
	} {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile("testdata/" + tt.file + ".lock")
			require.NoError(t, err)
			pkgs, deps, err := NewParser().Parse(t.Context(), strings.NewReader(string(data)))
			require.NoError(t, err)
			versions, names, edges := make(map[string]string), make(map[string]string), make(map[string][]string)
			for _, pkg := range pkgs {
				assert.NotContains(t, names, pkg.ID)
				names[pkg.ID], versions[pkg.Name] = pkg.Name, pkg.Version
				assert.Equal(t, "generic", pkg.Identifier.PURL.Type)
				assert.Equal(t, "alire", pkg.Identifier.PURL.Namespace)
				assert.Equal(t, []string{"Apache-2.0"}, pkg.Licenses)
				if pkg.Name == "leaf_dep" {
					assert.Equal(t, ftypes.RelationshipIndirect, pkg.Relationship)
				} else {
					assert.Equal(t, ftypes.RelationshipDirect, pkg.Relationship)
				}
			}
			for _, dep := range deps {
				require.Contains(t, names, dep.ID)
				for _, id := range dep.DependsOn {
					require.Contains(t, names, id, "no dangling graph edges")
					edges[names[dep.ID]] = append(edges[names[dep.ID]], names[id])
				}
			}
			assert.Equal(t, tt.versions, versions)
			assert.Equal(t, tt.edges, edges)
			again, againDeps, err := NewParser().Parse(t.Context(), strings.NewReader(string(data)))
			require.NoError(t, err)
			assert.Equal(t, pkgs, again)
			assert.Equal(t, deps, againDeps)
		})
	}
}

func TestParser_RejectUnsupportedEvidence(t *testing.T) {
	data, err := os.ReadFile("testdata/resolved.lock")
	require.NoError(t, err)
	valid := string(data)
	_, states, ok := strings.Cut(valid, "[[solution.state]]")
	require.True(t, ok)
	for _, tt := range []struct{ name, input, want string }{
		{"malformed", "[", "decode error"},
		{"unknown layout", "[future]\nversion=1", "unrecognized"},
		{"unattempted", strings.Replace(valid, "solved = true", "solved = false", 1), "unattempted"},
		{"unknown schema", "schema = 99\n" + valid, "unsupported ALIRE lockfile structure"},
		{"unknown state field", strings.Replace(valid, "pinned = false", "pinned = false\nfuture = true", 1), "unsupported ALIRE lockfile structure"},
		{"unknown fulfillment", strings.Replace(valid, `fulfilment = "solved"`, `fulfilment = "future"`, 1), "unknown fulfillment"}, //nolint:misspell // ALIRE serialized key.
		{"hinted external", strings.Replace(valid, `fulfilment = "solved"`, `fulfilment = "hinted"`, 1), "external"},                //nolint:misspell // ALIRE serialized key.
		{"missing version", strings.Replace(valid, `version = "1.0.0"`, `version = ""`, 1), "full semantic version"},
		{"constraint used as version", strings.Replace(valid, `version = "1.0.0"`, `version = "^1.0.0"`, 1), "full semantic version"},
		{"mismatched name", strings.Replace(valid, `name = "direct_dep"`, `name = "other_dep"`, 1), "names disagree"},
		{"stale version", strings.Replace(valid, `version = "1.0.0"`, `version = "9.0.0"`, 1), "disagrees"},
		{"duplicate state", valid + "[[solution.state]]" + states, "duplicate crate"},
		{"missing edge target", strings.Replace(valid, `leaf_dep = "^2.0.0"`, `absent_dep = "*"`, 1), "absent from resolution"},
		{"conditional", strings.Replace(valid, `leaf_dep = "^2.0.0"`, `"case(os)" = {linux = {leaf_dep = "^2.0.0"}}`, 1), "conditional"},
		{"unknown transitivity", strings.Replace(valid, `transitivity = "direct"`, `transitivity = "future"`, 1), "transitivity"},
		{"unsupported source", strings.Replace(valid, "file:<FIXTURE_DIR>/sources/direct_dep", "external:system", 1), "origin scheme"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs, deps, err := NewParser().Parse(t.Context(), strings.NewReader(tt.input))
			require.ErrorContains(t, err, tt.want)
			assert.Nil(t, pkgs)
			assert.Nil(t, deps)
		})
	}
	for _, file := range []string{"missed", "linked"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + file + ".lock")
			require.NoError(t, err)
			_, _, err = NewParser().Parse(t.Context(), strings.NewReader(string(data)))
			require.Error(t, err, "solved=true does not prove completeness or a linked version")
		})
	}
}

func TestMatchConstraint(t *testing.T) {
	for _, tt := range []struct {
		version, constraint string
		want                bool
	}{
		{"0.9.0", "^0.2", true}, {"1.0.0", "^0.2", false},
		{"0.2.9", "~0.2", true}, {"0.3.0", "~0.2", false},
		{"1.0.0", "*", true}, {"1.0.0", "=1.0", true},
		{"1.0.1", "=1.0.0", false}, {"1.0.1", "/=1.0.0", true},
		{"1.2.0", ">=1.0.0", true}, {"1.0.0", ">1.0.0", false},
		{"1.0.0", "<=1.0.0", true}, {"1.0.0", "<1.0.0", false},
		{"1.0.0-rc.1", ">=1.0.0", false}, {"1.0.0+build.1", "=1.0.0", true},
	} {
		t.Run(tt.version+"/"+tt.constraint, func(t *testing.T) {
			match, err := matchConstraint(tt.version, tt.constraint)
			require.NoError(t, err)
			assert.Equal(t, tt.want, match)
		})
	}
	for _, unsupported := range []string{"^1 & ~1", "1.*", "latest", "^v1.0.0"} {
		_, err := matchConstraint("1.0.0", unsupported)
		require.Error(t, err)
	}
}

func TestCrateName(t *testing.T) {
	for _, name := range []string{"abc", "1ab", strings.Repeat("a", 64)} {
		assert.True(t, crateName.MatchString(name), name)
	}
	for _, name := range []string{"ab", "_abc", "Abc", "a-b", strings.Repeat("a", 65)} {
		assert.False(t, crateName.MatchString(name), name)
	}
}

func TestLinkedResolverReturnsNil(t *testing.T) {
	data, err := os.ReadFile("testdata/linked.lock")
	require.NoError(t, err)
	root := &Manifest{
		Name: "linked_app", Version: "1.0.0",
		Dependencies: []map[string]any{{"direct_dep": "^1.0.0"}},
		Pins:         []map[string]any{{"direct_dep": map[string]any{"path": "../local_dep"}}},
	}
	parser := NewProjectParser(root, "linked/alire.toml", func(string) (*Manifest, string, error) {
		return nil, "", nil
	})
	_, _, err = parser.Parse(t.Context(), strings.NewReader(string(data)))
	require.ErrorContains(t, err, "linked manifest is unavailable")
}

func TestSourceIdentity(t *testing.T) {
	m := Manifest{Name: "private_dep", Version: "1.0.0+build.1", Origin: map[string]any{"url": "https://user:secret@example.invalid/a.tar.gz?token=secret#fragment-secret"}}
	one, err := releasePackage(m)
	require.NoError(t, err)
	assert.NotContains(t, one.ID, "secret")
	assert.NotContains(t, one.ID, "user")
	assert.NotContains(t, one.ID, "fragment-secret")
	assert.Equal(t, "https://example.invalid/a.tar.gz", one.Identifier.PURL.Qualifiers.Map()["download_url"])
	m.Origin["url"] = "https://example.invalid/another.tar.gz"
	two, err := releasePackage(m)
	require.NoError(t, err)
	assert.NotEqual(t, one.ID, two.ID, "same crate and version from different sources stay distinct")
	m.Origin["url"] = "https://example.invalid/a.tar.gz?source=another"
	query, err := releasePackage(m)
	require.NoError(t, err)
	assert.Equal(t, one.ID, query.ID, "query values may contain secrets and must not affect deterministic identity")
	assert.NotContains(t, query.ID, "source=another")
	m.Origin["url"] = "file:/private/host/cache/source"
	local, err := releasePackage(m)
	require.NoError(t, err)
	assert.NotContains(t, local.ID, "/private/")
	assert.Empty(t, local.ExternalReferences)
	m.Origin["url"] = "file:/another/private/source"
	otherLocal, err := releasePackage(m)
	require.NoError(t, err)
	assert.Equal(t, local.ID, otherLocal.ID, "private host paths must not affect deterministic identity")
	assert.NotEqual(t, ManifestPackage(m, "one/alire.toml").ID, ManifestPackage(m, "two/alire.toml").ID)
}
