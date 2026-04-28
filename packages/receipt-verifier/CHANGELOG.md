# Changelog — `@tessaliq/receipt-verifier`

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The library is currently `0.1.0-draft`. The `-draft` suffix will be removed and
the package promoted to `1.0.0` once a real receipt issued by an EUDI Wallet
(through the France Identité Playground or the EU AV reference app pilot) has
been verified end-to-end against the library — see `docs/technique/receipt-spec-v1.md` §10.

## [Unreleased]

### Added

- Contract drift detection (planned) — mirrored type test on the Tessaliq
  signer side to catch silent divergence between the signer payload and the
  library's `TessaliqReceiptClaims` interface (see `tessaliq` issue tracker).

## [0.1.0-draft] — 2026-04-20

### Added

- `verifyReceipt(jwt, options)` — verify a Tessaliq receipt JWT cryptographically
  using the public JWKS endpoint, with optional `jwks` for fully air-gapped use.
- Strict header check : `alg=ES256`, `kid=tessaliq-receipt-v1`, `typ=tessaliq-receipt+jwt`.
- Issuer check : default `https://api.tessaliq.com`, overridable via `expectedIssuer`.
- Application-layer claim structure validation (`session_id`, `organization_id`,
  `verification.{policy, policy_version, result, state, created_at, completed_at, assurance_level}`,
  `proof | null`, optional `dpv`).
- Typed error results : `invalid-signature`, `invalid-algorithm`, `invalid-issuer`,
  `invalid-structure`, `jwks-fetch-failed`, `unknown`.
- CLI `tessaliq-receipt-verify` — file or stdin input, configurable JWKS URL and
  issuer, exit codes `0` valid / `1` invalid / `2` usage error.
- Test suite covering happy path, tampered signature, wrong issuer, terminal
  states (`verified` / `failed`), `jti != session_id`, all four `assurance_level`
  values, ZK proof object, and non-JWT input rejection.
- README with installation instructions (git dependency / clone-and-link, npm
  publication is gated on Tessaliq incorporation).
- Receipt format specification synced with the signer at commit `16a6cc18`
  (cf. [`docs/technique/receipt-spec-v1.md`](../../docs/technique/receipt-spec-v1.md)).

### Spec status

- Spec stabilised on the v1.0-draft contract on 2026-04-20.
- Spec README install instructions tightened on 2026-04-20 (commit `ec3b67a`).

### Known limitations (per spec §9)

- No `exp` claim — receipts are permanent audit artifacts.
- `assurance_level` defaults to `unknown` until the wallet exposes it end-to-end.
- No revocation mechanism — handled by `kid` rotation if needed.
- Not yet published to npm (project policy, tied to incorporation timeline).

### Deferred to v1.0

- Real-wallet end-to-end example receipt embedded in the package examples
  (gated on France Identité Playground access or EU AV ref app stabilisation).
- Drop the `-draft` suffix from package version and from spec status.
- Third-party review of the spec (OWF / DIF / external EUDI implementer).
