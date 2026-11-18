# ADR-0018: The product is Sulayi, and the CLI is `sulayi attack`

- **Status:** Accepted
- **Date:** 2026-11-19
- **Supersedes:** [ADR-0011](0011-product-identity-application-security-framework.md)

## Context

The product direction changed from an assessment-coverage and verification layer
([ADR-0017](0017-reposition-to-coverage-and-verification.md)) to a local-first, autonomous
application penetration testing tool for developers testing their own applications before
deployment. The repository was renamed on GitHub to `jaylordibe/sulayi`.

A Go module path must match the repository it is fetched from, so the module path, the
binary, the configuration file and every identifier derived from the old name had to move
with the repository. Nothing was published under the old name: `0.1.0` is unreleased and
there are no tags, so no installation depends on the old module path.

## Decision

| | Before | After |
|---|---|---|
| Product name | Application Security Framework | Sulayi |
| Go module | `github.com/jaylordibe/application-security-framework` | `github.com/jaylordibe/sulayi` |
| CLI executable | `appsec` | `sulayi` |
| Assessment command | `appsec scan` | `sulayi attack` |
| Configuration file | `appsec.yaml` | `sulayi.yaml` |
| Configuration `apiVersion` | `appsec/v1alpha1` | `sulayi/v1alpha1` |
| Adapter contract | `appsec.adapter/v1alpha1` | `sulayi.adapter/v1alpha1` |
| Run directory | `.appsec/` | `.sulayi/` |
| Report, run and evidence schemas | `appsec.*/v1alpha1` | `sulayi.*/v1alpha1` |

`attack` is the single entry point for the whole assessment lifecycle. `scan` is removed
rather than kept as an alias: this is pre-1.0 with no external users, and an alias is a
second command to document and maintain.

There is no compatibility mode. Instead, the old names are recognised only to be refused
with a migration message: an `appsec.yaml` with no `sulayi.yaml` stops the run (ignoring it
would assess with defaults and silently drop the operator's scope, exclusions and
identities), and `apiVersion: appsec/v1alpha1` names the value to use.

The runs directory now writes its own `.gitignore`. The repository Sulayi runs from is
usually the application's own, whose ignore rules may cover `.appsec/` but cannot know about
`.sulayi/`; without this, a renamed tool would make committing evidence the default.

## Alternatives considered

**Keep `appsec` as an alias.** Rejected: maintenance for a user base of one, and it keeps
two names in every document.

**Read `appsec.yaml` when `sulayi.yaml` is absent.** Rejected: a silent fallback hides the
rename, and the file's `apiVersion` would then be wrong anyway.

## Consequences

- Historical records — earlier ADRs, `docs/evaluation/`, `docs/research/`, the `0.1.0`
  release notes and past changelog entries — keep the old name, because they describe what
  was true and run when they were written.
- Any consumer of `report.json`, `meta.json` or the SARIF properties sees new schema
  identifiers. Each schema carries its own version string, so a consumer detects the change
  rather than misparsing.
