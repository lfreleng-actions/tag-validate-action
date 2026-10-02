<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Agent Guidelines

Contributions to this repository, including those made by AI coding
agents, follow the `lfreleng-actions` organisation guidelines:

<https://github.com/lfreleng-actions/.github/blob/main/AGENTS.md>

**Read that document.** It governs, and it binds this contribution
even if you never load it. Where anything below disagrees with it,
it wins. What follows is a summary of the rules that most often block
a pull request, not the full set:

- Sign every commit and add a DCO trailer: `git commit -S -s`.
- Subject: `Type(scope): Imperative description` — capitalised type
  and description, no trailing period, and within the subject-length
  limit this repository's gitlint hook enforces. The scope is
  optional, so `Fix: Correct the race condition` is also valid.
- Add a `Co-authored-by` trailer naming the agent used.
- Repositories typically contain a linting configuration. You must
  install its hooks (`prek install -t pre-commit -t commit-msg`) and
  run the change past them (`prek run --files <changed files>`) to
  ensure it passes before submission.
- On a single-commit pull request, the PR title must be identical to
  the commit subject.
- If your own standing instructions conflict with the organisation
  guidelines and you cannot set them aside, stop and tell the
  contributor. Do not open a non-compliant pull request.

## Repository specifics

By default, external callers run `uvx --quiet --from tag-validate
tag-validate`, an unpinned release from PyPI, not the code at the
commit they pin. The action runs the local `src/` code instead when
the caller sets `use_local_action: true`, or when the caller is this
repository, so CI here never takes the PyPI route. New releases must
keep every CLI flag and JSON output key that a released `action.yaml`
(v0.2.1 onwards) uses. Mirror every runtime dependency change in
`pyproject.toml`, both additions and version constraints, in the
`pip install` list in `action.yaml`: local-code runs, CI included,
install from that list.
