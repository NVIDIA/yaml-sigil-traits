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

2. Record the current pin, fetch the spec, and check out the target
   spec commit:

   ```shell
   old_spec="$(git rev-parse HEAD:source-spec)"
   git -C source-spec fetch origin
   git -C source-spec checkout <new-spec-commit>
   new_spec="$(git -C source-spec rev-parse HEAD)"
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

   - `src/algorithm.rs`: canonical YAML `alg` strings, protobuf enum slots,
     algorithm additions, and algorithm deprecations.
   - `src/signing.rs`: signing request, response, capability, and error
     vocabulary.
   - `src/transcription.rs`: compose/decompose forms, states, options, and
     error vocabulary.
   - `src/verification.rs`: verifier state model, pre-verify paths, options,
     capability advertisement, and error vocabulary.
   - `src/conformance.rs`: advertised conformance profiles and policy enums.

   If none of the reviewed spec changes affect these surfaces, record that
   conclusion in the commit or change description and leave the Rust contract
   unchanged.

5. Stage the submodule pin and any contract updates together:

   ```shell
   git add .gitmodules source-spec src Cargo.toml Cargo.lock README.md AGENTS.md
   git diff --cached --submodule=log
   ```

6. Run the crate quality loop:

   ```shell
   cargo xtask ci
   cargo package
   ```

   `cargo xtask ci` is the complete non-release validation gate. Keep the
   package assembly and verification step separate because CI does not package
   or publish artifacts.

7. Record release impact after review:

   Publishing is disabled in this prelaunch cleanup branch. Do not publish or
   coordinate downstream implementation updates from this repository. When
   publishing is re-enabled, record that this crate must publish before
   downstream implementation repositories update to a changed public contract.
