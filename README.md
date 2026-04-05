# Tessaliq — Open Source Components

Zero-knowledge identity verification for European SaaS publishers. Verify identity attributes (age, nationality) via EUDI Wallet credentials without ever exposing personal data.

This repository contains the open-source building blocks of the [Tessaliq](https://tessaliq.com) platform.

## What's here

| Package | Description |
|---------|-------------|
| [`circuits/age_verification`](./circuits/age_verification/) | Noir ZK circuit — proves age ≥ threshold without revealing date of birth |
| [`packages/sdk-web`](./packages/sdk-web/) | Browser SDK — Digital Credentials API, EUDI Wallet deep link, client-side ZK proof generation |
| [`packages/sd-jwt`](./packages/sd-jwt/) | SD-JWT-VC parser and verifier (draft-ietf-oauth-selective-disclosure-jwt) |
| [`packages/shared`](./packages/shared/) | Shared TypeScript types |

## Why open source?

- **Trust**: clients can audit that ZK circuits don't leak personal data
- **Adoption**: an open SDK lowers the integration barrier for SaaS publishers
- **Standards**: SD-JWT and OpenID4VP are open standards — implementations should be too

## Quick start

### ZK Circuit (Noir)

```bash
cd circuits/age_verification
nargo test        # Run 6 unit tests
nargo compile     # Compile to ACIR
```

Requires [Noir](https://noir-lang.org/) 0.36.0.

### SDK & TypeScript packages

```bash
pnpm install
pnpm build
```

## Architecture

```
User's browser                    Tessaliq API (proprietary)
┌──────────────┐                 ┌──────────────────┐
│  sdk-web     │                 │  Session mgmt    │
│  ┌────────┐  │   1. session    │  Policy engine   │
│  │ Noir   │  │ ───────────────>│  Proof verifier  │
│  │ prover │  │                 │  Issuer registry │
│  └────────┘  │   4. proof      │  Receipt signer  │
│              │ ───────────────>│                  │
│  ┌────────┐  │                 └──────────────────┘
│  │ SD-JWT │  │   2. credential
│  │ parser │  │ <── EUDI Wallet
│  └────────┘  │
└──────────────┘
```

1. SDK creates a verification session via the API
2. Wallet presents an SD-JWT-VC credential (Digital Credentials API or deep link)
3. SDK parses the credential client-side, extracts date of birth
4. SDK generates a ZK proof (age ≥ threshold) and submits it to the API
5. API verifies the proof — **date of birth never leaves the browser**

## Standards

- [SD-JWT-VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) — Selective Disclosure JWT
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — Verifiable Presentations
- [DCQL](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) — Digital Credentials Query Language
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
- [eIDAS 2.0 / EUDI Wallet](https://ec.europa.eu/digital-building-blocks/sites/display/EUDIGITALIDENTITYWALLET)

## Version locks

```
nargo:                          0.36.0
@noir-lang/noir_js:             0.36.0
@noir-lang/backend_barretenberg: 0.36.0
```

These versions must stay in sync. A mismatch causes serialization errors.

## License

MIT — see [LICENSE](./LICENSE).

## About Tessaliq

Tessaliq is a zero-knowledge identity verification platform for European SaaS publishers, built on EUDI Wallet and eIDAS 2.0 standards. The full platform (API, dashboard, compliance engine) is proprietary.

- Website: [tessaliq.com](https://tessaliq.com)
- Contact: olivier@tessaliq.com
