# Contributing to yaml-sigil-traits

`yaml-sigil-traits` is developed agent-first. Use agents to explore the trait
and DTO contract, compare it to the pinned specification, and draft changes,
then review the result as the responsible author before submitting it.

## The Critical Rule

**You must understand your code.** AI-assisted contributions are welcome, but
you must be able to explain what changed, why it changed, and how it affects the
public trait and DTO contract. Do not submit generated code, tests, or
documentation that you cannot defend without the agent open.

## AI Usage

`yaml-sigil-traits` is agent-first, not agent-only.

- **Do** use agents to read the crate, compare specification vocabulary, run
  checks, generate drafts, and iterate on implementations.
- **Do** use the skills in `.agents/skills/`; they capture repository-specific
  workflows for spec pin updates and trait contract review.
- **Do** question the agent until you understand the compatibility impact, edge
  cases, and downstream implementation impact of your change.
- **Do not** submit changes you cannot explain in your own words.
- **Do not** use agents as a substitute for reading the relevant code, specs,
  and maintainer guidance.
