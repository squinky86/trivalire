package alire

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ManifestPackage identifies local metadata by its location within the artifact.
// It does not claim that the manifest describes a previously built binary.
func ManifestPackage(m Manifest, manifestPath string) ftypes.Package {
	return newPackage(m, "local:"+manifestPath)
}

func newPackage(m Manifest, source string) ftypes.Package {
	// This is a locator digest, not a source-content hash or integrity assertion.
	// ALIRE's resolution does not retain the supplying index. Do not infer one.
	p := packageurl.NewPackageURL(packageurl.TypeGeneric, "alire", m.Name, m.Version,
		packageurl.Qualifiers{{Key: "alire_source", Value: fmt.Sprintf("%x", sha256.Sum256([]byte(source)))}}, "")
	pkg := ftypes.Package{
		ID: p.String(), Name: m.Name, Version: m.Version,
		Identifier: ftypes.PkgIdentifier{PURL: p},
	}
	if m.Licenses != "" {
		pkg.Licenses = []string{m.Licenses}
	}
	return pkg
}

func releasePackage(m Manifest) (ftypes.Package, error) {
	raw, ok := m.Origin["url"].(string)
	if !ok || raw == "" {
		return ftypes.Package{}, xerrors.New("release has no static source origin")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ftypes.Package{}, xerrors.New("invalid release origin URL")
	}
	switch u.Scheme {
	case "file", "http", "https", "git+https", "git+http":
	default:
		return ftypes.Package{}, xerrors.New("unsupported release origin scheme")
	}
	if u.Scheme != "file" && u.Hostname() == "" {
		return ftypes.Package{}, xerrors.New("release origin has no host")
	}
	// Credentials are not part of source identity. Query strings can select
	// different source archives, so retain them only inside the opaque digest.
	u.User = nil
	identityURL := u.String()
	u.RawQuery, u.Fragment = "", ""
	origin := make(map[string]any, len(m.Origin))
	for key, value := range m.Origin {
		switch key {
		case "url":
			origin[key] = identityURL
		case "commit", "subdir", "archive-name":
			if _, ok := value.(string); !ok {
				return ftypes.Package{}, xerrors.New("non-static origin metadata")
			}
			origin[key] = value
		case "hashes":
			hashes, ok := value.([]any)
			if !ok {
				return ftypes.Package{}, xerrors.New("invalid origin hashes")
			}
			for _, hash := range hashes {
				if _, ok := hash.(string); !ok {
					return ftypes.Package{}, xerrors.New("invalid origin hash")
				}
			}
			origin[key] = value
		default:
			return ftypes.Package{}, xerrors.New("unsupported origin metadata")
		}
	}
	data, err := json.Marshal(origin)
	if err != nil {
		return ftypes.Package{}, xerrors.Errorf("origin encoding error: %w", err)
	}
	pkg := newPackage(m, string(data))
	if u.Scheme != "file" {
		typ := ftypes.RefOther
		qualifier := "download_url"
		if strings.HasPrefix(u.Scheme, "git+") || origin["commit"] != nil {
			typ = ftypes.RefVCS
			qualifier = "vcs_url"
		}
		pkg.ExternalReferences = []ftypes.ExternalRef{{Type: typ, URL: u.String()}}
		pkg.Identifier.PURL.Qualifiers = append(pkg.Identifier.PURL.Qualifiers,
			packageurl.Qualifier{Key: qualifier, Value: u.String()})
		pkg.ID = pkg.Identifier.PURL.String()
	}
	return pkg, nil
}
