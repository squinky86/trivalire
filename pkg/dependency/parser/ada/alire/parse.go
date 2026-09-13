package alire

import (
	"context"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type state struct {
	Crate        string         `toml:"crate"`
	Fulfillment  string         `toml:"fulfilment"` //nolint:misspell // ALIRE's serialized field spelling.
	Transitivity string         `toml:"transitivity"`
	Versions     string         `toml:"versions"`
	Pinned       *bool          `toml:"pinned"`
	PinVersion   string         `toml:"pin_version"`
	Reason       string         `toml:"reason"`
	Release      *Manifest      `toml:"release"`
	Link         map[string]any `toml:"link"`
}

// LinkResolver reads a linked manifest from the artifact, returning its relative
// path for identity. A parser never reads the host filesystem itself.
type LinkResolver func(string) (*Manifest, string, error)

type Parser struct {
	root        *Manifest
	rootPath    string
	resolveLink LinkResolver
}

func NewParser() *Parser { return &Parser{} }

func NewProjectParser(root *Manifest, rootPath string, resolveLink LinkResolver) *Parser {
	return &Parser{root: root, rootPath: rootPath, resolveLink: resolveLink}
}

func (p *Parser) Parse(ctx context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lock struct {
		Solution struct {
			Context struct {
				Solved *bool `toml:"solved"`
			} `toml:"context"`
			States []state `toml:"state"`
		} `toml:"solution"`
	}
	meta, err := toml.NewDecoder(r).Decode(&lock)
	if err != nil {
		return nil, nil, xerrors.Errorf("lockfile decode error: %w", err)
	}
	if lock.Solution.Context.Solved == nil || !*lock.Solution.Context.Solved {
		return nil, nil, xerrors.New("unrecognized or unattempted ALIRE resolution")
	}
	// There is no schema-version discriminator in ALIRE 2.1.1. Reject unknown
	// resolution fields; non-inventory release metadata can be ignored.
	for _, key := range meta.Undecoded() {
		if strings.Contains(key.String(), "case(") && len(key) >= 4 && key[3] == "depends-on" {
			return nil, nil, xerrors.New("conditional dependencies are unsupported")
		}
		if supportedKey(key) {
			continue
		}
		return nil, nil, xerrors.New("unsupported ALIRE lockfile structure")
	}
	return p.inventory(ctx, lock.Solution.States)
}

func supportedKey(key toml.Key) bool {
	if len(key) < 3 || key[0] != "solution" || key[1] != "state" {
		return false
	}
	if key[2] == "link" {
		return true // Nested dynamic tables are explicitly checked below.
	}
	if len(key) < 4 || key[2] != "release" {
		return false
	}
	return ignoredMetadata(key[3]) || key[3] == "depends-on" || key[3] == "pins" || key[3] == "origin"
}

func ignoredMetadata(key string) bool {
	switch key {
	case "description", "long-description", "authors", "maintainers", "maintainers-logins", "website", "tags",
		"project-files", "executables", "gpr-externals", "gpr-set-externals", "auto-gpr-with", "actions",
		"environment", "configuration", "build-switches", "build-profiles", "available":
		return true
	default:
		return false
	}
}

func (p *Parser) inventory(ctx context.Context, states []state) ([]ftypes.Package, []ftypes.Dependency, error) {
	pkgs := make(map[string]ftypes.Package)
	manifests := make(map[string]*Manifest)
	stateByName := make(map[string]state)
	for _, s := range states {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if _, ok := pkgs[s.Crate]; ok {
			return nil, nil, xerrors.New("ambiguous duplicate crate in ALIRE resolution")
		}
		pkg, m, err := p.statePackage(s)
		if err != nil {
			return nil, nil, xerrors.Errorf("crate %s: %w", s.Crate, err)
		}
		pkgs[s.Crate], manifests[s.Crate], stateByName[s.Crate] = pkg, m, s
	}

	if p.root != nil {
		if _, ok := pkgs[p.root.Name]; ok {
			return nil, nil, xerrors.New("root crate also appears in resolution")
		}
		root := ManifestPackage(*p.root, p.rootPath)
		root.Relationship = ftypes.RelationshipRoot
		pkgs[root.Name], manifests[root.Name] = root, p.root
		if err := p.validatePins(stateByName); err != nil {
			return nil, nil, err
		}
	}

	var packages ftypes.Packages
	var dependencies ftypes.Dependencies
	for name, m := range manifests {
		declared, err := m.dependencies()
		if err != nil {
			return nil, nil, err
		}
		pkg := pkgs[name]
		var edges []string
		for depName, constraint := range declared {
			dep, ok := pkgs[depName]
			if !ok {
				return nil, nil, xerrors.Errorf("dependency %s is absent from resolution", depName)
			}
			if depName == name {
				return nil, nil, xerrors.New("self dependency in ALIRE evidence")
			}
			// A local override intentionally ignores the declared version range.
			if stateByName[depName].Fulfillment == "linked" {
				edges = append(edges, dep.ID)
				continue
			}
			if match, err := matchConstraint(dep.Version, constraint); err != nil {
				return nil, nil, err
			} else if !match {
				return nil, nil, xerrors.Errorf("selected version disagrees with dependency on %s", depName)
			}
			edges = append(edges, dep.ID)
		}
		sort.Strings(edges)
		packages = append(packages, pkg)
		if len(edges) > 0 {
			dependencies = append(dependencies, ftypes.Dependency{ID: pkg.ID, DependsOn: edges})
		}
	}
	if p.root != nil {
		if err := p.validateGraph(states, manifests); err != nil {
			return nil, nil, err
		}
	}
	sort.Sort(packages)
	sort.Sort(dependencies)
	return packages, dependencies, nil
}

func (p *Parser) statePackage(s state) (ftypes.Package, *Manifest, error) {
	if !crateName.MatchString(s.Crate) || s.Pinned == nil || s.Versions == "" {
		return ftypes.Package{}, nil, xerrors.New("incomplete resolution state")
	}
	pkg, m, err := p.selectedPackage(s)
	if err != nil {
		return pkg, nil, err
	}
	if err = m.validate(); err != nil {
		return pkg, nil, err
	}
	if m.Name != s.Crate {
		return pkg, nil, xerrors.New("crate and manifest names disagree")
	}
	if len(m.Pins) > 0 {
		return pkg, nil, xerrors.New("pins in dependency manifests are unsupported")
	}
	if *s.Pinned && s.PinVersion != m.Version || !*s.Pinned && s.PinVersion != "" {
		return pkg, nil, xerrors.New("inconsistent version pin")
	}
	if s.Fulfillment != "linked" {
		if match, err := matchConstraint(m.Version, s.Versions); err != nil {
			return pkg, nil, err
		} else if !match {
			return pkg, nil, xerrors.New("selected version disagrees with resolution constraint")
		}
	}
	switch s.Transitivity {
	case "direct":
		pkg.Relationship = ftypes.RelationshipDirect
	case "indirect":
		pkg.Relationship, pkg.Indirect = ftypes.RelationshipIndirect, true
	default:
		return pkg, nil, xerrors.New("unsupported dependency transitivity")
	}
	return pkg, m, nil
}

func (p *Parser) selectedPackage(s state) (ftypes.Package, *Manifest, error) {
	switch s.Fulfillment {
	case "solved":
		if s.Release == nil || len(s.Link) > 0 {
			return ftypes.Package{}, nil, xerrors.New("solved state requires a release")
		}
		pkg, err := releasePackage(*s.Release)
		return pkg, s.Release, err
	case "linked":
		return p.linkedPackage(s)
	default:
		return ftypes.Package{}, nil, xerrors.New("unresolved, external, or unknown fulfillment state")
	}
}

func (p *Parser) linkedPackage(s state) (ftypes.Package, *Manifest, error) {
	if s.Release != nil || p.resolveLink == nil {
		return ftypes.Package{}, nil, xerrors.New("linked manifest is unavailable")
	}
	for key := range s.Link {
		if key != "path" && key != "lockfiled" {
			return ftypes.Package{}, nil, xerrors.New("remote or unknown link form is unsupported")
		}
	}
	if lockfiled, ok := s.Link["lockfiled"].(bool); !ok || !lockfiled {
		return ftypes.Package{}, nil, xerrors.New("unrecognized linked state structure")
	}
	linkPath, ok := s.Link["path"].(string)
	if !ok || linkPath == "" {
		return ftypes.Package{}, nil, xerrors.New("linked state requires a local path")
	}
	m, manifestPath, err := p.resolveLink(linkPath)
	if err != nil {
		return ftypes.Package{}, nil, err
	}
	if m == nil {
		return ftypes.Package{}, nil, xerrors.New("linked manifest is unavailable")
	}
	return ManifestPackage(*m, manifestPath), m, nil
}

func (p *Parser) validatePins(states map[string]state) error {
	seen := make(map[string]bool)
	for _, table := range p.root.Pins {
		for name, value := range table {
			s, ok := states[name]
			pin, isTable := value.(map[string]any)
			if !ok || !isTable || len(pin) != 1 || seen[name] {
				return xerrors.New("unsupported or inconsistent manifest pin")
			}
			seen[name] = true
			if version, ok := pin["version"].(string); ok {
				if !*s.Pinned || version != s.PinVersion {
					return xerrors.New("manifest and resolution version pins disagree")
				}
			} else if path, ok := pin["path"].(string); ok {
				if s.Fulfillment != "linked" || path != s.Link["path"] {
					return xerrors.New("manifest and resolution local pins disagree")
				}
			} else {
				return xerrors.New("remote or unknown manifest pin is unsupported")
			}
		}
	}
	for name, s := range states {
		if (*s.Pinned || s.Fulfillment == "linked") && !seen[name] {
			return xerrors.New("resolution pin is absent from root manifest")
		}
	}
	return nil
}

func (p *Parser) validateGraph(states []state, manifests map[string]*Manifest) error {
	direct, err := p.root.dependencies()
	if err != nil {
		return err
	}
	for _, s := range states {
		_, isDirect := direct[s.Crate]
		if isDirect != (s.Transitivity == "direct") {
			return xerrors.New("manifest and resolution direct dependencies disagree")
		}
	}
	visited := make(map[string]bool)
	queue := []string{p.root.Name}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if visited[name] {
			continue
		}
		visited[name] = true
		deps, err := manifests[name].dependencies()
		if err != nil {
			return err
		}
		for dep := range deps {
			queue = append(queue, dep)
		}
	}
	if len(visited) != len(manifests) {
		return xerrors.New("resolution contains dependencies unreachable from the manifest")
	}
	return nil
}
