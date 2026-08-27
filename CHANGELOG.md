# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0-rc.2](https://github.com/NVIDIA/yaml-sigil-traits/compare/v0.4.0-rc.1...v0.4.0-rc.2) - 2026-08-27

### Added

- *(xtask)* consolidate release automation

### Fixed

- *(release)* verify cargo-binstall version
- *(ci)* isolate protected fork validation
- *(ci)* require author DCO signoff
- *(ci)* bound protected validation resources
- *(xtask)* require Clap 4.6
- *(ci)* complete Cargo target policy
- *(ci)* harden protected validation
- *(release)* bind proposal intent and validation
- *(ci)* reconcile protected check state ([#36](https://github.com/NVIDIA/yaml-sigil-traits/pull/36))
- *(ci)* harden protected candidate policy ([#35](https://github.com/NVIDIA/yaml-sigil-traits/pull/35))
- *(ci)* retire copied-head validation
- *(ci)* disable copied pull request syncing

### Other

- enforce dependency policy with cargo-deny
- validate signed fork contributions
- *(xtask)* derive release command parsing
- *(release)* adopt Rust automation
- *(release)* preserve reviewed commit signatures
- *(release)* harden official automation
- add protected pull request validation
- *(signing)* clarify capability surface

## [0.4.0-rc.1](https://github.com/NVIDIA/yaml-sigil-traits/compare/v0.3.0-rc.2...v0.4.0-rc.1) - 2026-08-21

### Fixed

- *(release)* require copied-head CI for snapshots

### Other

- *(api)* explain implementation key bindings
- *(api)* explain key binding probes
- *(api)* [**breaking**] abstract cryptographic key types
- migrate Linux jobs to NVIDIA runners

## [0.3.0-rc.2](https://github.com/NVIDIA/yaml-sigil-traits/compare/v0.3.0-rc.1...v0.3.0-rc.2) - 2026-08-20

### Added

- *(release)* automate release candidates and snapshots

### Fixed

- *(release)* configure proposal registry index
- *(release)* configure proposal dry-run forge
- *(release)* attach proposal recheck branch
- *(release)* distinguish absent proposal branch
- *(release)* stage App-signed commit
- *(release)* verify unreferenced App commit
- *(release)* use App commit signing API
- *(release)* bind signed commit to staging ref
- *(release)* attach proposal source branch
- *(release)* restore proposal and snapshot validation

### Other

- improve crate discovery and reader guidance
- enable copied pull request testing

## [0.3.0-rc.1](https://github.com/NVIDIA/yaml-sigil-traits/releases/tag/v0.3.0-rc.1) - 2026-08-18

### Fixed

- *(verification)* align empty-signature precedence
- *(algorithm)* reject noncanonical YAML identifiers
- *(security)* mirror signature carrier safeguards

### Other

- *(release)* prepare yaml-sigil-traits 0.3.0-rc.1
- add minimal cross-platform tests
- use anonymous specification checkout
- validate trusted pull requests
- allow manual validation
- align crate package contents
- add hosted and local validation
- update repository URLs after transfer
- *(markdown)* remove stale rumdl exclusions
- *(metadata)* add crates.io contact
- *(msrv)* clarify Rust toolchain policy
- *(agents)* require conventional commits
- *(markdown)* exclude externally managed templates
- name project in code of conduct
- add code of conduct
- *(spec)* pin conformance coverage updates
- *(spec)* pin application security clarification
- *(spec)* pin licensing compliance update
- *(spec)* pin security clarification
- *(spec)* advance pinned specification
- *(licensing)* correct RFC and SEC material attribution
- bump crate version to 0.3.0-rc.1
- *(spec)* pin agent documentation standards
- align agent documentation with standards
- *(spec)* pin marker defense clarification
- *(spec)* pin nested signature security link
- *(spec)* pin carrier marker clarification
- *(spec)* pin unreachable scan clarification
- record YAML streaming limitation
- state artifact recognition contract
- *(spec)* pin document-end marker clarification
- *(spec)* pin EOF check clarification
- *(spec)* pin schema profile clarification
- *(verification)* clarify nested signature content
- *(spec)* pin security considerations
- *(verification)* bind keys to authorized algorithms
- sync contribution sign-off guidance
- update specification license pin
- add contribution sign-off guidance
- update specification attribution pin
- update specification notice pin
- initial port
- *(license)* update boilerplate
- Initial commit
