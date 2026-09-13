package alire

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/mod/semver"
	"golang.org/x/xerrors"
)

var crateName = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{2,63}$`)

// Manifest contains inventory evidence, not instructions to execute a project.
type Manifest struct {
	Name         string           `toml:"name"`
	Version      string           `toml:"version"`
	Licenses     string           `toml:"licenses"`
	Dependencies []map[string]any `toml:"depends-on"`
	Pins         []map[string]any `toml:"pins"`
	Origin       map[string]any   `toml:"origin"`
	Provides     []string         `toml:"provides"`
	External     any              `toml:"external"`
}

func ParseManifest(r io.Reader) (*Manifest, error) {
	var m Manifest
	meta, err := toml.NewDecoder(r).Decode(&m)
	if err != nil {
		return nil, xerrors.Errorf("manifest decode error: %w", err)
	}
	for _, key := range meta.Undecoded() {
		// TOML leaves nested interface-valued tables undecoded in MetaData;
		// these are validated by dependencies, validatePins and releasePackage.
		if len(key) > 0 && (key[0] == "pins" || key[0] == "depends-on" || key[0] == "origin") {
			continue
		}
		if len(key) == 0 || !ignoredMetadata(key[0]) {
			return nil, xerrors.New("unsupported ALIRE manifest structure")
		}
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m Manifest) validate() error {
	if !crateName.MatchString(m.Name) || !validVersion(m.Version) {
		return xerrors.New("manifest requires a crate name and a full semantic version")
	}
	return nil
}

func (m Manifest) dependencies() (map[string]string, error) {
	if len(m.Provides) > 0 || m.External != nil {
		return nil, xerrors.New("external and provided crates are unsupported")
	}
	deps := make(map[string]string)
	for _, table := range m.Dependencies {
		for name, value := range table {
			constraint, ok := value.(string)
			if !ok || !crateName.MatchString(name) {
				return nil, xerrors.New("conditional or non-static dependencies are unsupported")
			}
			if _, exists := deps[name]; exists {
				return nil, xerrors.Errorf("duplicate dependency %s", name)
			}
			deps[name] = constraint
		}
	}
	return deps, nil
}

func validVersion(v string) bool {
	core, _, _ := strings.Cut(v, "-")
	core, _, _ = strings.Cut(core, "+")
	return strings.Count(core, ".") == 2 && semver.IsValid("v"+v)
}

// matchConstraint deliberately accepts only simple ALIRE constraints. In
// particular, ALIRE's caret keeps the same major even for 0.x (unlike Cargo).
// Compound version sets require separate support; never approximate them.
func matchConstraint(version, constraint string) (bool, error) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "*" {
		return true, nil
	}
	op := "="
	for _, prefix := range []string{"/=", ">=", "<=", "^", "~", "=", ">", "<"} {
		if strings.HasPrefix(constraint, prefix) {
			op = prefix
			constraint = strings.TrimSpace(strings.TrimPrefix(constraint, prefix))
			break
		}
	}
	// Only constraints may abbreviate a version; package versions must be full.
	if !semver.IsValid("v" + constraint) {
		return false, xerrors.New("unsupported ALIRE version constraint")
	}
	v, c := "v"+version, "v"+constraint
	comparison := semver.Compare(v, c)
	switch op {
	case "=":
		return comparison == 0, nil
	case "/=":
		return comparison != 0, nil
	case ">":
		return comparison > 0, nil
	case ">=":
		return comparison >= 0, nil
	case "<":
		return comparison < 0, nil
	case "<=":
		return comparison <= 0, nil
	case "^":
		return comparison >= 0 && semver.Major(v) == semver.Major(c), nil
	case "~":
		return comparison >= 0 && semver.MajorMinor(v) == semver.MajorMinor(c), nil
	default:
		return false, fmt.Errorf("unsupported constraint operator %s", op)
	}
}
