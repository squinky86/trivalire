# Pixi lockfile fixtures

`pixi.lock` is a synthetic, offline fixture exercising two Conda platforms,
multiple environments, PyPI version changes, checksums, license evidence,
cross-ecosystem dependencies, and an unused global package record. The
`example.org` URLs and repeated-byte hashes are test data, not downloadable
packages or verified checksums.

The `upstream-v*.lock` files retain two complete package records from Pixi's own
lockfiles, with the environment selection reduced to those records. Metadata is
unchanged; omitted dependencies deliberately do not become invented packages.
Sources (Pixi is BSD-3-Clause licensed):

- v5: https://github.com/prefix-dev/pixi/blob/bd9f4a91110e0f80ec6dc32354baf446df5219c0/pixi.lock (v0.30.0)
- v6: https://github.com/prefix-dev/pixi/blob/9bc64afdc98333d56d56dd8d6d530ae6d559846e/pixi.lock (v0.41.4)
- v7: https://github.com/prefix-dev/pixi/blob/27402ba80139a04095a1f69e406ccad3ff8843a5/pixi.lock

For v5/v6 select the first two package records. For v7 select the first Conda
record and first PyPI record. Set `environments.default.packages.linux-64` to
references to the two records, retaining `version` and `packages`. This can be
reproduced with any YAML reader/writer; tests do not require Python or Pixi.

## Verification

Run from the Trivy repository root:

```sh
go test ./pkg/dependency/parser/conda/pixi ./pkg/fanal/analyzer/language/conda/pixi ./pkg/detector/library ./pkg/sbom/...
go test -tags integration ./integration -run '^(TestPixi.*|TestConvert|TestSBOM)$' -count=1
go test -race ./pkg/dependency/parser/conda/pixi ./pkg/fanal/analyzer/language/conda/pixi ./pkg/detector/library ./pkg/sbom/core ./pkg/sbom/io ./pkg/sbom/spdx
go test ./pkg/dependency/parser/conda/pixi -run '^$' -fuzz FuzzParse -fuzztime 30s -parallel 2
```

The Pixi CLI tests use a temporary, fixture-backed vulnerability database. They
cover lockfile discovery, nested projects, directory exclusions, installed
rootfs environments, license findings, vulnerability reports and filtering,
exit codes, and CycloneDX/SPDX/JSON round trips. They do not download package
sources or require Pixi, Docker, or a live vulnerability database.
