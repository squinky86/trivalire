package alire

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/ada/alire"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeAlire, newAlireAnalyzer)
}

const version = 1

type alireAnalyzer struct {
	logger *log.Logger
}

func newAlireAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &alireAnalyzer{logger: log.WithPrefix("alire")}, nil
}

func (*alireAnalyzer) Type() analyzer.Type { return analyzer.TypeAlire }
func (*alireAnalyzer) Version() int        { return version }

func (*alireAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	filePath = filepath.ToSlash(filePath)
	switch path.Base(filePath) {
	case types.AlireToml:
		return !generatedPath(path.Dir(filePath))
	case types.AlireLock:
		return path.Base(path.Dir(filePath)) == "alire" && !generatedPath(path.Dir(path.Dir(filePath)))
	default:
		return false
	}
}

// ALIRE's generated/deployed metadata is evidence for its owning workspace,
// not a set of additional projects. Legacy root-level locks are not supported.
func generatedPath(dir string) bool {
	for _, generated := range []string{"cache", "builds", "releases", "tmp"} {
		if strings.Contains("/"+dir+"/", "/alire/"+generated+"/") {
			return true
		}
	}
	return false
}

func (a *alireAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	files, manifests, locks, err := a.collectFiles(ctx, input.FS)
	if err != nil {
		return nil, xerrors.Errorf("ALIRE walk error: %w", err)
	}

	result := &analyzer.AnalysisResult{}
	processed, linked := make(map[string]bool), make(map[string]bool)
	// Pair only the exact project/alire.toml and project/alire/alire.lock.
	for _, lockPath := range locks {
		manifestPath := path.Join(path.Dir(path.Dir(lockPath)), types.AlireToml)
		processed[manifestPath] = true
		root, err := readManifest(files, manifestPath)
		if err != nil {
			a.incomplete(ctx, lockPath, err)
			continue
		}
		var linkedManifests []string
		resolveLink := func(link string) (*alire.Manifest, string, error) {
			manifest, err := linkedPath(manifestPath, link)
			if err != nil {
				return nil, "", err
			}
			m, err := readManifest(files, manifest)
			if err == nil {
				linkedManifests = append(linkedManifests, manifest)
			}
			return m, manifest, err
		}
		parser := alire.NewProjectParser(root, manifestPath, resolveLink)
		app, err := language.Parse(ctx, types.Alire, lockPath, bytes.NewReader(files[lockPath]), parser)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			a.incomplete(ctx, lockPath, err)
			app = rootApplication(root, manifestPath)
		} else {
			// Suppress standalone linked roots only when their inventory was
			// actually retained in this project's complete graph.
			for _, manifest := range linkedManifests {
				linked[manifest] = true
			}
		}
		if app != nil {
			result.Applications = append(result.Applications, *app)
		}
	}

	for _, manifestPath := range manifests {
		if processed[manifestPath] || linked[manifestPath] {
			continue
		}
		root, err := readManifest(files, manifestPath)
		if err != nil {
			a.incomplete(ctx, manifestPath, err)
			continue
		}
		// A manifest never proves transitive resolution, even with exact versions.
		if len(root.Dependencies) > 0 || len(root.Pins) > 0 {
			a.incomplete(ctx, manifestPath, xerrors.New("alire/alire.lock is absent"))
		}
		result.Applications = append(result.Applications, *rootApplication(root, manifestPath))
	}
	sort.Slice(result.Applications, func(i, j int) bool {
		return result.Applications[i].FilePath < result.Applications[j].FilePath
	})
	return result, nil
}

func (a *alireAnalyzer) collectFiles(ctx context.Context, fsys fs.FS) (map[string][]byte, []string, []string, error) {
	// Only regular files collected from the artifact can be used as evidence.
	// Keeping this allowlist also prevents a local pin from following a symlink
	// through an FS implementation that otherwise permits it.
	files := make(map[string][]byte)
	var manifests, locks []string
	err := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if !entry.Type().IsRegular() || !a.Required(name, nil) {
			return nil
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		files[name] = data
		if path.Base(name) == types.AlireToml {
			manifests = append(manifests, name)
		} else {
			locks = append(locks, name)
		}
		return nil
	})
	return files, manifests, locks, err
}

func (a *alireAnalyzer) incomplete(ctx context.Context, filePath string, err error) {
	a.logger.WarnContext(ctx, "Incomplete ALIRE inventory: dependency graph omitted; only available root metadata is retained",
		log.FilePath(filePath), log.Err(err))
}

func rootApplication(root *alire.Manifest, manifestPath string) *types.Application {
	pkg := alire.ManifestPackage(*root, manifestPath)
	pkg.Relationship = types.RelationshipRoot
	return &types.Application{Type: types.Alire, FilePath: manifestPath, Packages: types.Packages{pkg}}
}

func readManifest(files map[string][]byte, name string) (*alire.Manifest, error) {
	data, ok := files[name]
	if !ok {
		return nil, xerrors.New("manifest is unavailable inside the scanned artifact")
	}
	return alire.ParseManifest(bytes.NewReader(data))
}

func linkedPath(rootManifest, link string) (string, error) {
	// Reject absolute paths on every host OS, including drive/UNC paths. Never
	// translate a host path into an artifact path or consult ALIRE's host cache.
	if link == "" || path.IsAbs(link) || strings.ContainsAny(link, `\:`) {
		return "", xerrors.New("only artifact-relative local pins are supported")
	}
	manifest := path.Join(path.Dir(rootManifest), link, types.AlireToml)
	if !fs.ValidPath(manifest) || generatedPath(path.Dir(manifest)) {
		return "", xerrors.New("local pin is outside the supported artifact boundary")
	}
	return manifest, nil
}
