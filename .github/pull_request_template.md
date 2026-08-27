<!-- Use a Conventional Commit-style title and keep it within 72 characters. -->

# Pull Request

## Why

- Explain the problem or need this change addresses.

## What changed

- Summarize the substantive changes.

## Review guide

- Tell reviewers where to start and identify the highest-risk or most
  important parts of the change.

## Compatibility impact

- Describe API, schema, wire-format, MSRV, or behavioral compatibility
  effects. Write `None` when there are none.

## Dependency and licensing impact

- Describe dependency, license, package-content, or third-party-notice
  effects. Write `None` when there are none.

## Related issue

- Link a related issue when one exists.

## Testing

- List the exact commands run and their results.

## Checklist

- [ ] I confirmed this belongs in the Rust API-contract repository and is
  neither a language-neutral specification change better handled in
  [yaml-sigil-spec](https://github.com/NVIDIA/yaml-sigil-spec) nor
  implementation work better handled in
  [yaml-sigil-rs](https://github.com/NVIDIA/yaml-sigil-rs).
- [ ] I have the right to submit this contribution, every commit is GitHub
  Verified, and every commit includes a `Signed-off-by` trailer that exactly
  matches its Git author.
- [ ] I understand and can explain this change.
- [ ] I updated documentation or tests where needed.
- [ ] I reviewed `CONTRIBUTING.md` and `SECURITY.md`.
