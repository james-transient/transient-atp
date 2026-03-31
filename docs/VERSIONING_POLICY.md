# ATP Versioning Policy

## Scope

This policy defines semantic versioning for ATP protocol artifacts, schemas, and conformance tooling.

## Protocol Versioning

- MAJOR: breaking changes to ATP protocol semantics, required fields, or conformance outcomes.
- MINOR: backward-compatible additions (new optional fields, new non-breaking checks, new scenarios).
- PATCH: clarifications, bug fixes, and non-semantic corrections.

## Package Versioning

- `@atp/spec` and `@atp/conformance-cli` use SemVer.
- Package MAJOR versions MUST align with compatible ATP protocol major version.
- Package release notes MUST explicitly identify protocol compatibility.

## Compatibility Guarantees

- ATP 1.x conformance contracts MUST remain backward-compatible within major version unless explicitly marked as a breaking release.
- Breaking behavior changes require:
  - MAJOR bump
  - migration notes
  - updated conformance expectations

## Deprecation Rules

- Deprecated fields or checks MUST remain supported for at least one MINOR release cycle before removal.
- Deprecations MUST be documented in release notes and conformance docs.
