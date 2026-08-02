# Tessaliq — Open Source Components (archived)

> **This project is archived and no longer maintained.**
>
> Tessaliq ran from March 2026 to August 2026. The company behind it is being
> wound down and all hosted services have been shut off. This repository is kept
> online as a public record of the work. It is not maintained, issues and pull
> requests are not monitored, and nothing here should be treated as production
> software.
>
> The code remains under the MIT licence — fork it, read it, reuse it freely.

Tessaliq was an attempt to build a zero-knowledge identity verification service
for European SaaS publishers: verify an identity attribute (mainly age) against
EUDI Wallet credentials without exposing personal data to the relying party.

This repository holds the components that were open source. The API, dashboard
and compliance engine were proprietary and are not published.

---

## Why it was stopped

Not for technical reasons. The verifier worked and passed conformance testing.

The problem was that a standalone verifier turned out to be a poor place to build
a business. Accepting wallet credentials became a feature absorbed into existing
identity products rather than a product of its own, and the platform wallets
(Google, Apple) took the consumer volume. Open standards did their job: they made
this layer interoperable, and therefore non-differentiating. By mid-2026 several
established vendors shipped the same capability within weeks of each other.

The decision to stop was made in August 2026, from a stable position, without
having run customer interviews — that gap is worth stating plainly, since it means
the market hypothesis was never directly tested, only inferred from the ecosystem.

---

## What actually worked

Stated precisely, because these claims are checkable and it would be easy to
overstate them:

- **OpenID4VP verifier conformance** — 24/24 modules PASSED across the four
  OpenID Foundation OID4VP verifier test plans, in immutable runs dated
  2026-05-08.
- **OID4VCI issuer (mdoc)** — the HAIP test plan run returned 55 PASSED,
  4 REVIEW and 1 WARNING. It was submitted but never validated by the OIDF.
- **No certification was ever purchased.** The OIDF self-certification fee was
  considered and declined. Nothing here is certified — the runs are reproducible
  evidence, not a badge.
- **mdoc / ISO 18013-5 attribute check** (`eu.europa.ec.av.1` age verification
  profile) was the production path, validated end to end against the France
  Identité partner sandbox.
- **Receipt specification** — a signed, self-contained proof of verification that
  a third party could audit without depending on Tessaliq.

## What never shipped

- **The zero-knowledge path was never enabled in production.** It sat behind
  `ZK_PATH_ENABLED=false` from the April 2026 pivot onwards. The Noir circuit
  compiles and its tests pass, but it was an opt-in alpha, never a live code path.
  Earlier versions of this README described the ZK flow as the main architecture;
  that was aspirational and is corrected below.
- **`@tessaliq/receipt-verifier` was never published to npm.** The package reached
  `v1.0.0` in this repository (tagged 2026-05-13) and the spec it implements is
  stable, but the npm release never happened — the name is unregistered. Any
  installation instructions referring to a published package are wrong; use it
  from source.
- **`status_list` revocation** was never wired into the mdoc MSO.
- Noir was pinned at **0.36.0** throughout and never migrated to the 1.0 line.

---

## What's here

| Package | Description | State |
|---------|-------------|-------|
| [`circuits/age_verification`](./circuits/age_verification/) | Noir ZK circuit — proves age ≥ threshold without revealing date of birth | Compiles, tests pass, never enabled in production |
| [`packages/sdk-web`](./packages/sdk-web/) | Browser SDK — Digital Credentials API, EUDI Wallet deep link, client-side proof generation | Used in production for the mdoc path |
| [`packages/sd-jwt`](./packages/sd-jwt/) | SD-JWT-VC parser and verifier | Working |
| [`packages/receipt-verifier`](./packages/receipt-verifier/) | Verifies Tessaliq receipt JWTs from the public JWKS alone, with no dependency on Tessaliq at verification time | `v1.0.0`, stable spec, never published to npm |
| [`packages/shared`](./packages/shared/) | Shared TypeScript types | — |

## Architecture as actually deployed

The production flow was an **mdoc attribute check**, not a ZK proof:

```
User's browser                    Tessaliq API (proprietary, now offline)
┌──────────────┐                 ┌──────────────────┐
│  sdk-web     │   1. session    │  Session mgmt    │
│              │ ───────────────>│  Policy engine   │
│              │                 │  mdoc verifier   │
│              │   2. mdoc VP    │  Issuer registry │
│              │ ───────────────>│  Receipt signer  │
└──────────────┘                 └──────────────────┘
        ↑
        │ EUDI Wallet (OpenID4VP)
```

1. SDK opens a verification session against the API
2. Wallet presents an mdoc credential over OpenID4VP
3. API verifies the issuer signature and the requested attribute (`age_over_NN`)
4. API returns a signed receipt — the date of birth is never disclosed to the
   relying party

The ZK variant replaced step 3 with a client-side Noir proof. It is present in
this repository but was never the live path.

---

## Running the code

Nothing here talks to a live Tessaliq service any more — the API, the demo and
the mock wallet have all been shut down. The circuit and the TypeScript packages
still build and test on their own.

```bash
# ZK circuit
cd circuits/age_verification
nargo test        # 6 unit tests
nargo compile     # compile to ACIR

# TypeScript packages
pnpm install
pnpm build
```

### Version locks

```
nargo:                           0.36.0
@noir-lang/noir_js:              0.36.0
@noir-lang/backend_barretenberg: 0.36.0
```

These three must stay in sync or you get serialization errors. Note that Noir has
since moved well past this version — expect breaking changes if you upgrade.

> **Security note:** a Barretenberg vulnerability disclosed in March 2026 was
> classified critical for Noir. A fix shipped in the v5 line (July 2026). The
> pinned 0.36.0 toolchain here predates that fix. The ZK path was never enabled in
> production, so nothing deployed was exposed — but do not use these pinned
> versions for anything real.

---

## Standards implemented

- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) — mdoc, the production credential format
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — Verifiable Presentations
- [DCQL](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) — Digital Credentials Query Language
- [SD-JWT-VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) — Selective Disclosure JWT
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
- [eIDAS 2.0 / EUDI Wallet](https://ec.europa.eu/digital-building-blocks/sites/display/EUDIGITALIDENTITYWALLET)

## License

MIT — see [LICENSE](./LICENSE). Unchanged by the archival.

---

*Archived August 2026. The website, demo and API are offline; links to
`tessaliq.com` in older files no longer resolve.*
