# Acknowledgements

## Signing and Key Distribution

ATP's signing model — Ed25519 with canonical JSON serialization — draws on established patterns in the agent attestation and verifiable credentials space, including:

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) — Ed25519 signatures and linked-data proof conventions.
- [JSON Web Signatures (RFC 7515)](https://datatracker.ietf.org/doc/html/rfc7515) and [JSON Web Key (RFC 7517)](https://datatracker.ietf.org/doc/html/rfc7517) — JWKS key distribution shape and `kid` key identifier conventions.
- [JSON Canonicalization Scheme (RFC 8785)](https://datatracker.ietf.org/doc/html/rfc8785) — structural influence on ATP's `ATP-JCS-SORTED-UTF8` canonicalization algorithm.
- [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and [RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174) — normative language conventions throughout this specification.

## Governance Model and Policy Enforcement

ATP's Policy Enforcement Point (PEP) architecture and `allow`/`approve`/`deny` decision semantics draw on the inline enforcement patterns demonstrated by [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw) (Apache 2.0). NemoClaw's OpenShell gateway intercepts agent actions at runtime and routes them through operator approval gates — a concrete, working example of the enforcement model that ATP formalises as a protocol-level contract. ATP extends this pattern by defining canonical Intent, Decision, and Receipt objects so that governance decisions become machine-verifiable artifacts, not just runtime state.

## What is Original to ATP

The Intent → Decision → Receipt lifecycle, stable immutable identifiers, machine-verifiable conformance framework, and the claim that a receipt is only valid if the governance decision is co-present — these are original to ATP and are not covered by signing protocols, credential issuance standards, or sandbox orchestration tools.

---

ATP is developed and maintained by Transient Intelligence Ltd (https://transientintelligence.com). Protocol contributions, feedback, and independent implementations are welcome.
