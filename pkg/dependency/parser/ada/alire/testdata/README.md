# ALIRE resolution fixtures

These Apache-2.0 metadata-only fixtures were generated with ALIRE 2.1.1
(`fa9a1a9971d159f8cb2b8007dbb73e9e029fc109`). No third-party source is included.
The official Linux archive SHA-256 is
`09c66bcd8c35dd4b97b72c3d9b76e44caa6964a2db35aba069f396f00f1f64c7`.

To regenerate, supply that verified binary and a new output directory:

```sh
python3 generate.py /absolute/path/to/alr /tmp/new-alire-fixtures
```

The script creates an isolated local index and settings profile, and runs
`alr -n -C <project> with --solve`. Go tests do not invoke the generator, ALIRE,
an Ada compiler, or the network. Copy the generated `.lock` files here and
`.txtar` files to `pkg/fanal/analyzer/language/ada/alire/testdata/`.

The temporary workspace prefix in source origins is replaced with
`<FIXTURE_DIR>`, and trailing blank lines are removed. Linked paths remain
relative. The linked fixture deliberately
selects `direct_dep@3.1.0` despite a `^1.0.0` declaration: ALIRE local overrides
ignore version constraints. Its `pinned` flag is false. The missed fixture has
`solved=true` and an unresolved state even though `with --solve` exited zero.
The unresolved fixture was never solved and has no lockfile.

Parser tests also make explicitly synthetic mutations to these genuine inputs
to check malformed, unsupported, and inconsistent evidence and source identity.
