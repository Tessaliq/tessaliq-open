# Changelog — `@tessaliq/receipt-verifier`

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-13

### Added

- `examples/real-receipt.json` — a real Tessaliq receipt minted by the
  staging verifier (`api-staging.tessaliq.com`) on 2026-05-13, alongside the
  JWKS snapshot used to sign it, for fully reproducible air-gapped
  verification. The credential being verified was issued by the Tessaliq
  Reusable AV (ex-Variante C) issuer and presented via the
  [`Tessaliq/mock-wallet`](https://github.com/Tessaliq/mock-wallet) OID4VP
  `direct_post` flow under the `eu_av_blueprint` profile.
- `__tests__/real-receipt.test.ts` — end-to-end air-gapped verification test
  that exercises `verifyReceipt(receipt, { jwks })` against the bundled
  fixture, plus two negative paths (substitute key under same `kid` →
  `invalid-signature`; wrong `expectedIssuer` → `invalid-issuer`).

### Changed

- Promoted from `0.1.0-draft` to `1.0.0`. The promotion gate stated in spec
  §10 (verify a receipt issued via a real EUDI Wallet end-to-end with this
  library) is now met by the bundled `examples/real-receipt.json` fixture
  and the corresponding test. The spec is updated to `v1.0` in the same
  release.

### Removed

- The "Deferred to v1.0" section from `0.1.0-draft` — all gating items
  except "third-party review of the spec" are now done. External review
  remains welcome via the issue tracker but is no longer a release gate.

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
