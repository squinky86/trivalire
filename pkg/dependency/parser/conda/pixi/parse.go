// Package pixi reads resolved Pixi inventories without executing Pixi or fetching packages.
package pixi

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

type lockfile struct {
	Version      int                    `yaml:"version"`
	Environments map[string]environment `yaml:"environments"`
	Packages     []record               `yaml:"packages"`
}
type environment struct {
	Packages map[string][]reference `yaml:"packages"`
}
type reference struct {
	Conda string `yaml:"conda"`
	PyPI  string `yaml:"pypi"`
}
type record struct {
	Locations    types.Locations `yaml:"-"`
	reference    `yaml:",inline"`
	Kind         string   `yaml:"kind"`
	URL          string   `yaml:"url"`
	Name         string   `yaml:"name"`
	Version      string   `yaml:"version"`
	Build        string   `yaml:"build"`
	Subdir       string   `yaml:"subdir"`
	License      string   `yaml:"license"`
	SHA256       string   `yaml:"sha256"`
	MD5          string   `yaml:"md5"`
	Depends      []string `yaml:"depends"`
	RequiresDist []string `yaml:"requires_dist"`
	PURLs        []string `yaml:"purls"`
}

// UnmarshalYAML retains the record's location for JSON/SARIF evidence.
func (r *record) UnmarshalYAML(node *yaml.Node) error {
	type plainRecord record
	var decoded plainRecord
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*r = record(decoded)
	r.Locations = types.Locations{{StartLine: node.Line, EndLine: lastLine(node)}}
	return nil
}
func lastLine(node *yaml.Node) int {
	line := node.Line
	if node.Kind == yaml.ScalarNode {
		line += strings.Count(node.Value, "\n")
	}
	for _, child := range node.Content {
		line = max(line, lastLine(child))
	}
	return line
}

func (r reference) key() (string, string, error) {
	switch {
	case r.Conda != "" && r.PyPI == "":
		return "conda", r.Conda, nil
	case r.PyPI != "" && r.Conda == "":
		return "pypi", r.PyPI, nil
	default:
		return "", "", fmt.Errorf("expected exactly one conda or pypi reference")
	}
}

// Parse supports rattler lock versions 5, 6 and 7. Each environment/platform is
// kept separate: joining their dependency graphs would invent impossible edges.
func Parse(ctx context.Context, filename string, reader io.Reader) ([]types.Application, error) {
	var lock lockfile
	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&lock); err != nil {
		return nil, fmt.Errorf("decode pixi.lock: %w", err)
	}
	if lock.Version < 5 || lock.Version > 7 {
		return nil, fmt.Errorf("unsupported pixi.lock version %d (supported: 5-7)", lock.Version)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("pixi.lock must contain one YAML document")
	}
	if lock.Environments == nil {
		return nil, fmt.Errorf("pixi.lock has no environments")
	}

	index, err := indexPackages(ctx, lock)
	if err != nil {
		return nil, err
	}
	var apps []types.Application
	for _, env := range sortedKeys(lock.Environments) {
		for _, platform := range sortedKeys(lock.Environments[env].Packages) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			app, err := index.application(filename, env, platform, lock.Environments[env].Packages[platform])
			if err != nil {
				return nil, err
			}
			if len(app.Packages) > 0 {
				apps = append(apps, app)
			}
		}
	}
	return apps, nil
}

type packageIndex struct {
	records  map[string]record
	packages map[string]types.Package
}

func indexPackages(ctx context.Context, lock lockfile) (*packageIndex, error) {
	index := &packageIndex{records: make(map[string]record), packages: make(map[string]types.Package)}
	for _, rec := range lock.Packages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if lock.Version == 5 {
			switch rec.Kind {
			case "conda":
				rec.Conda = rec.URL
			case "pypi":
				rec.PyPI = rec.URL
			default:
				return nil, fmt.Errorf("unsupported package kind %q", rec.Kind)
			}
		}
		kind, source, err := rec.key()
		if err != nil {
			return nil, err
		}
		key := kind + ":" + source
		if _, exists := index.records[key]; exists {
			return nil, fmt.Errorf("duplicate %s package record", kind)
		}
		pkg, err := rec.packageInfo()
		if err != nil {
			return nil, err
		}
		index.records[key], index.packages[key] = rec, pkg
	}
	return index, nil
}

func (index *packageIndex) application(filename, env, platform string, refs []reference) (types.Application, error) {
	app := types.Application{Type: types.Pixi, FilePath: fmt.Sprintf("%s (%s/%s)", filename, env, platform)}
	selected := make(map[string]types.Package)
	names := make(map[string]string)
	for _, ref := range refs {
		kind, source, err := ref.key()
		if err != nil {
			return app, err
		}
		key := kind + ":" + source
		pkg, ok := index.packages[key]
		if !ok {
			return app, fmt.Errorf("unresolved %s reference in %s/%s", kind, env, platform)
		}
		nameKey := kind + ":" + pkg.Name
		if old, ok := names[nameKey]; ok && old != pkg.ID {
			return app, fmt.Errorf("ambiguous package %s in %s/%s", pkg.Name, env, platform)
		}
		names[nameKey], selected[key] = pkg.ID, pkg
	}
	index.addPythonAliases(selected, names)
	for _, key := range sortedKeys(selected) {
		pkg := selected[key]
		pkg.DependsOn = index.records[key].dependencies(names)
		app.Packages = append(app.Packages, pkg)
	}
	return app, nil
}

// Explicit Conda PyPI mappings permit cross-ecosystem edges but do not make a
// Conda build a PyPI vulnerability candidate. Ambiguous mappings are omitted.
func (index *packageIndex) addPythonAliases(selected map[string]types.Package, names map[string]string) {
	aliases := make(map[string]string)
	for _, key := range sortedKeys(selected) {
		if !strings.HasPrefix(key, "conda:") {
			continue
		}
		pkg := selected[key]
		for _, raw := range index.records[key].PURLs {
			p, err := packageurl.FromString(raw)
			if err != nil || p.Type != packageurl.TypePyPi || p.Namespace != "" {
				continue
			}
			nameKey := "pypi:" + python.NormalizePkgName(p.Name, true)
			if _, explicit := names[nameKey]; explicit {
				continue
			}
			if previous, exists := aliases[nameKey]; exists && previous != pkg.ID {
				aliases[nameKey] = ""
			} else {
				aliases[nameKey] = pkg.ID
			}
		}
	}
	for name, id := range aliases {
		if id != "" {
			names[name] = id
		}
	}
}

func (r record) dependencies(names map[string]string) []string {
	kind, _, _ := r.key() // Validated while indexing.
	requirements := r.Depends
	if kind == "pypi" {
		requirements = r.RequiresDist
	}
	var deps []string
	for _, requirement := range requirements {
		// Conditional Python requirements are not proof of a resolved edge.
		// Inventory still includes every selected package, including extras.
		if kind == "pypi" && strings.Contains(requirement, ";") {
			continue
		}
		name := requirementName(requirement, kind)
		if id, ok := names[kind+":"+name]; ok {
			deps = append(deps, id)
		}
	}
	slices.Sort(deps)
	return slices.Compact(deps)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+`)

func requirementName(s, kind string) string {
	if _, rest, ok := strings.Cut(s, "::"); ok {
		s = rest
	}
	name := namePattern.FindString(strings.TrimSpace(s))
	if kind == "pypi" {
		return python.NormalizePkgName(name, true)
	}
	return name
}

func (r record) packageInfo() (types.Package, error) {
	kind, source, err := r.key()
	if err != nil {
		return types.Package{}, err
	}
	u, err := url.Parse(source)
	if err != nil {
		return types.Package{}, fmt.Errorf("invalid %s package source URL", kind)
	}
	// Never put credentials or signed query strings into exported identifiers.
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	safeSource := u.String()
	qs := map[string]string{"download_url": safeSource}
	if kind == "conda" {
		if err := r.fillCondaMetadata(u); err != nil {
			return types.Package{}, err
		}
		qs["build"], qs["subdir"] = r.Build, r.Subdir
	} else {
		r.Name = python.NormalizePkgName(r.Name, true)
	}
	if r.Name == "" || r.Version == "" {
		return types.Package{}, fmt.Errorf("%s package missing name or version", kind)
	}
	pkg := types.Package{Name: r.Name, Version: r.Version, Licenses: licensing.SplitLicenses(r.License), Locations: r.Locations}
	if r.SHA256 != "" {
		if !validHash(r.SHA256, 32) {
			return types.Package{}, fmt.Errorf("invalid SHA-256 for %s", r.Name)
		}
		pkg.Digest = digest.NewDigestFromString(digest.SHA256, strings.ToLower(r.SHA256))
	} else if r.MD5 != "" {
		if !validHash(r.MD5, 16) {
			return types.Package{}, fmt.Errorf("invalid MD5 for %s", r.Name)
		}
		pkg.Digest = digest.NewDigestFromString(digest.MD5, strings.ToLower(r.MD5))
	}
	if pkg.Digest != "" {
		qs["checksum"] = string(pkg.Digest)
	}
	p := packageurl.NewPackageURL(kind, "", r.Name, r.Version, packageurl.QualifiersFromMap(qs), "")
	pkg.Identifier.PURL = p
	pkg.ID = p.String()
	return pkg, nil
}
func validHash(s string, length int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == length
}

func (r *record) fillCondaMetadata(u *url.URL) error {
	file := path.Base(u.Path)
	if r.Name == "" || r.Version == "" || r.Build == "" {
		if !strings.HasSuffix(file, ".conda") && !strings.HasSuffix(file, ".tar.bz2") {
			return fmt.Errorf("Conda package lacks metadata and an archive filename")
		}
	}
	file = strings.TrimSuffix(strings.TrimSuffix(file, ".tar.bz2"), ".conda")
	parts := strings.Split(file, "-")
	if len(parts) >= 3 {
		if r.Name == "" {
			r.Name = strings.Join(parts[:len(parts)-2], "-")
		}
		if r.Version == "" {
			r.Version = parts[len(parts)-2]
		}
		if r.Build == "" {
			r.Build = parts[len(parts)-1]
		}
	}
	if r.Subdir == "" {
		r.Subdir = path.Base(path.Dir(u.Path))
	}
	return nil
}
