---
name: yaml-sigil-traits-spec-update
description: Use when updating the pinned yaml-sigil-spec submodule in yaml-sigil-traits or reconciling its public trait and DTO vocabulary after YamlSigil specification changes.
---

# yaml-sigil-traits Spec Update

## Purpose

`yaml-sigil-traits` owns the portable Rust trait and DTO contract for YamlSigil
implementations. It mirrors the normative `yaml-sigil-spec` vocabulary, but it
does not own the specification, generate protobuf code, or coordinate
downstream implementation changes.

Use this skill when the `source-spec/` submodule pin changes or when reviewing
a proposed specification update for impact on this crate.

## Invariants

- Use the public GitHub URL for the `source-spec` remote.
- Treat `source-spec/` as read-only in this repository.
- Keep normal Cargo builds independent of `source-spec/`.
- Keep the submodule's default update strategy set to `none`. Override it only
  for an explicit specification-maintenance checkout.
- Do not add dependencies on `yaml-sigil-rs`, `yaml-sigil-core`, or generated
  protobuf crates.
- Do not add or reintroduce a custom publishing wrapper.
- Keep updates scoped to this crate's public trait, DTO, capability, and error
  vocabulary.
- Leaving the trait and DTO surface unchanged is a valid outcome when the spec
  delta does not require contract changes in this crate.

## Workflow

1. Start from a clean worktree and initialize the submodule if needed:

   ```shell
   git status --short
   git -c submodule.source-spec.update=checkout \
     submodule update --init source-spec
   git -C source-spec remote -v
   ```

2. Record the current pin, fetch the spec, resolve the requested target to a
   full commit ID, and check out that commit. Use `origin/main` when the request
   asks for the latest default branch and does not name a narrower target:

   ```shell
   old_spec="$(git rev-parse HEAD:source-spec)"
   git -C source-spec fetch --prune origin
   new_spec="$(git -C source-spec rev-parse '<target-spec-ref>^{commit}')"
   git -C source-spec checkout --detach "$new_spec"
   ```

3. Review the spec delta that can affect trait vocabulary. Treat this as a
   starting point, not a closed list. First inspect the full repository diff
   stat so unlisted spec files are not missed:

   ```shell
   git -C source-spec diff --stat "$old_spec..$new_spec"
   ```

   Then inspect the known trait-relevant paths:

   ```shell
   git -C source-spec diff --stat "$old_spec..$new_spec" -- \
     README.md \
     signing-api.md \
     verification-api.md \
     transcription-api.md \
     transcoding.md \
     base64-requirements.md \
     algorithms/ \
     proto/yaml_sigil/v1alpha1/ \
     schema/YamlSigilSignature.v1alpha1.schema.json \
     conformance/
   ```

   Review any unlisted changed files that could affect public trait, DTO,
   capability, or error vocabulary. Update this path list when code moves,
   spec files take ownership of vocabulary this crate mirrors, or a spec update
   reveals a cleaner review path.

4. Map spec changes to the crate surface:

   - `src/lib.rs`: crate-level contract documentation, modules, and re-exports.
   - `src/algorithm.rs`: canonical YAML `alg` strings, protobuf enum slots,
     algorithm additions, and algorithm deprecations.
   - `src/signing.rs`: signing request, response, capability, and error
     vocabulary, including implementation-owned signing key types.
   - `src/transcription.rs`: compose/decompose forms, states, options, and
     error vocabulary.
   - `src/verification.rs`: verifier state model, pre-verify paths, options,
     capability advertisement, error vocabulary, and implementation-owned
     verification key types.
   - `src/conformance.rs`: advertised conformance profiles and policy enums.
   - `tests/key_bindings.rs`: generic key DTO behavior, associated key types,
     object safety, and async returned-future bounds.
   - `README.md`: human-facing contract and implementation key-binding
     guidance.

   If none of the reviewed spec changes affect these surfaces, record that
   conclusion in the commit or change description and leave the Rust contract
   unchanged.

   Every pin update must also replace the full commit ID in the README link to
   `source-spec/THIRD_PARTY_NOTICES.md`, even when the Rust contract remains
   unchanged. Keep the separately scoped notice and the package exclusion
   language intact.

5. Stage the submodule pin and required README update, then stage each exact
   contract or test path you changed:

   ```shell
   git add source-spec README.md
   git status --short
   git diff --cached --submodule=log
   ```

   Stage only intended paths. Do not stage the generated root `Cargo.lock`;
   this repository deliberately ignores it.

6. Run the crate quality loop:

   ```shell
   cargo xtask ci
   cargo package --allow-dirty
   ```

   `cargo xtask ci` is the complete non-release validation gate. Keep the
   package assembly and verification step separate because CI does not package
   or publish artifacts. The pre-commit package check needs `--allow-dirty`
   because this workflow leaves the reviewed update uncommitted. When the task
   includes creating a commit, rerun `cargo package` without `--allow-dirty`
   after committing.

7. Record release impact after review:

   State whether the public contract changed and identify its compatibility
   impact. Do not edit the package version, prepare a release, or publish from
   an ordinary specification-update branch. A maintainer selects the version
   and uses the separate repository-root `RELEASING.md` workflow. Record that a
   changed public contract requires this crate's release to precede downstream
   implementation adoption.

   Publish only a crates.io `.crate` source package. Do not distribute compiled
   native executables, executable WebAssembly, installers, containers, retained
   CI or build outputs, GitHub Release assets, or separately generated source
   archives. Local and ephemeral compilation remains permitted for validation.
