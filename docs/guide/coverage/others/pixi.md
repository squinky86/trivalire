# Pixi

Trivy scans the resolved Conda and PyPI packages in [Pixi](https://pixi.sh/)
`pixi.lock` files. It reads the existing lockfile without running Pixi, installing
packages, reading package-manager caches, or downloading package sources.

| Packages | SBOM | Vulnerability | License |
|----------|:----:|:-------------:|:-------:|
| Conda    | ✓    | -             | ✓      |
| PyPI     | ✓    | ✓             | ✓      |

Lockfile scanning is enabled for **filesystem and repository** targets. Like
other development lockfiles, it is disabled for image and rootfs targets.
Installed packages in Pixi environments remain covered by the existing Conda
metadata and Python installed-package analyzers in image/rootfs scans where
those files are present. Filesystem/repository scans use development lockfiles
by default, following Trivy’s existing target selection rules.

## Usage

```console
trivy fs --scanners vuln,license /path/to/project
trivy fs --format cyclonedx --output pixi.cdx.json /path/to/project
trivy fs --format spdx-json --output pixi.spdx.json /path/to/project
trivy repo --format cyclonedx --output pixi.cdx.json /path/to/repository
```

For vulnerability findings in CycloneDX, explicitly enable the scanner:

```console
trivy fs --scanners vuln --format cyclonedx --output pixi.cdx.json /path/to/project
trivy sbom --scanners vuln pixi.cdx.json
```

The usual severity filtering, ignore policies, VEX filtering, exit codes, and
report formats apply to PyPI findings. License scanning uses the metadata in the
lockfile; it does not infer an unrecorded license or fetch package archives.
Secret and misconfiguration scanning continue to operate independently on files
supported by their respective scanners. There are no Pixi-specific
misconfiguration checks.

## Supported inventory

The analyzer supports [rattler lockfile](https://pixi.sh/latest/workspace/lock_file/)
versions **5, 6, and 7**, including compact Conda records whose name, version,
build, and subdirectory are encoded in the archive URL. Both `.conda` and
`.tar.bz2` archives are recognized. PyPI records must provide a name and version;
archive, VCS, and local sources are inventoried without accessing the source.
Conda source-build records using structured source objects are not supported.

Every environment and target platform recorded in the lockfile is inventoried,
including test and development environments. Results are named, for example,
`pixi.lock (default/linux-64)`. Dependencies selected for one environment/platform
are never resolved against another. Unreferenced records in the global package
pool are excluded. Multiple versions, Conda builds, platforms, and sources retain
separate identities. Nested projects are scanned independently.

`pixi.toml` and `pyproject.toml` alone are not resolved dependency inventories and
are not scanned by this analyzer. The lockfile does not identify the workspace
package or reliably distinguish direct, transitive, and development-only
packages. All selected dependencies are included, their relationship to the
workspace remains unknown, and `--include-dev-deps` does not change this
inventory. Trivy does not assert that the lockfile matches the current manifest
or the installed environment.

Malformed files, unsupported lockfile versions, duplicate package records,
ambiguous resolutions, invalid checksums, and references to absent package
records produce an **Incomplete Pixi inventory** warning. The affected lockfile
is omitted rather than reporting a partial inventory as complete. Other files
continue to be scanned. Inspect warnings as well as the command's exit status.

## Dependency graph and SBOM

Trivy preserves Conda `depends` edges and unconditional PyPI `requires_dist`
edges when the dependency exists in the same environment/platform. Explicit
Conda `purls` mappings can resolve Python dependencies to Conda packages.
Constraints are not dependency edges, and virtual platform packages such as
`__glibc` are not invented as installed components.

Conditional Python requirements containing environment markers are omitted from
the graph: presence of a package alone does not prove that a conditional edge
was active. Missing dependency targets are also omitted. These limitations affect
the graph, not the inventory of selected packages or vulnerability scanning.
Dependency edges do not imply that Trivy validated version constraints.

Conda packages use `pkg:conda` PURLs and PyPI packages use normalized `pkg:pypi`
PURLs. Qualifiers retain the recorded source (`download_url`), Conda `build` and
`subdir`, and a `checksum` where supplied. URL user information and query strings
are removed. Sources differing only in removed data may share an identity if
there is no distinguishing checksum. Local paths are recorded as supplied but
are never followed. VCS fragments are retained to distinguish revisions.

Recorded SHA-256 hashes (preferred) or MD5 hashes are exported as package hashes.
They describe the locked archive, not the lockfile or an independently verified
installation. The original record's line range is available in native JSON.

CycloneDX and SPDX JSON output preserve inventory, source-aware identities,
standard SPDX licenses, package hashes, and the supported dependency edges.
Trivy’s standard license normalization applies; arbitrary license text may be
represented by an SPDX `LicenseRef` rather than its original spelling. Both formats can
be read and re-exported, including cross-format conversion. The native JSON
intermediate used by `trivy convert` also preserves these fields:

```console
trivy sbom --scanners license --format json --output pixi.json pixi.cdx.json
trivy convert --format spdx-json --output pixi.spdx.json pixi.json
```

## Vulnerability coverage

Only PyPI records are matched against Trivy's Python advisory sources, using
PEP 440 version comparisons. As with other Python lockfiles, matching uses the
recorded package name/version and does not verify that a private, local, or VCS
source is equivalent to the public PyPI release.

**Conda vulnerability matching is not supported.** Trivy emits a warning when a
vulnerability scan includes Conda packages. A Conda package is never treated as
a PyPI release merely because its name matches, or because the lockfile includes
a PyPI PURL mapping. This avoids misleading findings for Conda builds. An SBOM
entry or an empty vulnerability report does not establish vulnerability coverage
for Conda packages.
