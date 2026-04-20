# @tessaliq/receipt-verifier

Verify Tessaliq receipt JWTs cryptographically, **offline, without calling the Tessaliq API**. MIT-licensed.

Tessaliq is an EUDI Wallet verifier that emits a signed JWT receipt after every verification. This library lets any third party — an auditor, a Relying Party, a regulator, a curious developer — check that a given receipt is authentic and has not been tampered with, using only the public JWKS published by Tessaliq.

> **Status** : v0.1.0-draft. The spec is being stabilised (see [docs/technique/receipt-spec-v1.md](https://github.com/Tessaliq/tessaliq-open/blob/main/docs/technique/receipt-spec-v1.md)). API may evolve before v1.0. Not yet published to npm (cf. project policy).

## Why this exists

A Tessaliq receipt is meant to be an **audit artifact**, not an opaque boolean. When a regulator (ARCOM, CNIL) or an auditor asks a Relying Party for proof that a given age verification was performed correctly, the RP hands over the receipt JWT. Without this library, the auditor would have to reimplement JWS verification against the Tessaliq JWKS. With it, the check is three lines of code.

The library **never calls the Tessaliq API**. The only network request it performs (optional) is to the public `.well-known/jwks.json` endpoint to fetch the signing key. You can also pre-fetch the JWKS and pass it as an option for a fully offline verification (useful for air-gapped audits).

## Install

```bash
pnpm add @tessaliq/receipt-verifier
# or npm install / yarn add
```

Requires Node.js ≥ 20.

## Usage — library

```ts
import { verifyReceipt } from '@tessaliq/receipt-verifier'

const result = await verifyReceipt(jwt)

if (result.valid) {
  console.log('Policy applied:', result.claims.verification.policy)
  console.log('Result:', result.claims.verification.result)
  console.log('Completed at:', result.claims.verification.completed_at)
} else {
  console.error(`Receipt invalid [${result.error}]: ${result.message}`)
}
```

### Options

```ts
verifyReceipt(jwt, {
  jwksUrl: 'https://api-staging.tessaliq.com/.well-known/jwks.json', // default: production
  expectedIssuer: 'https://api.tessaliq.com',                         // default: production
  // ...or skip the network entirely:
  jwks: { keys: [ /* pre-fetched public key(s) */ ] },
})
```

## Usage — CLI

```bash
# Verify a receipt stored in a file
tessaliq-receipt-verify receipt.jwt

# Pipe it
cat receipt.jwt | tessaliq-receipt-verify --stdin

# Point at staging
tessaliq-receipt-verify receipt.jwt \
  --jwks-url https://api-staging.tessaliq.com/.well-known/jwks.json \
  --issuer   https://api-staging.tessaliq.com
```

Exit code is `0` for valid, `1` for invalid, `2` for usage errors.

## What verification proves

A successful verification proves:

- The JWT was signed by the private key matching the current Tessaliq public key (`kid: tessaliq-receipt-v1`).
- The claims (policy, result, timestamps, proof hash, DPV) have not been modified since signature.
- The structure matches the Tessaliq receipt schema v1.

It does **not** prove:

- That the session exists in the Tessaliq database (there is no public lookup endpoint in v1).
- That Tessaliq's internal logic correctly applied the declared policy (this is established separately via public [OIDF conformance plans](https://demo.certification.openid.net/), the open-core primitives, and the [ENISA position paper](https://www.enisa.europa.eu)).

See [spec §8 — Garanties apportées par le receipt](https://github.com/Tessaliq/tessaliq-open/blob/main/docs/technique/receipt-spec-v1.md#8-garanties-apportées-par-le-receipt) for the full scope of guarantees.

## Related

- **Tessaliq** — EUDI Wallet verifier. [https://tessaliq.com](https://tessaliq.com)
- **Spec** — [docs/technique/receipt-spec-v1.md](https://github.com/Tessaliq/tessaliq-open/blob/main/docs/technique/receipt-spec-v1.md)
- **Public key (JWKS)** — [https://api.tessaliq.com/.well-known/jwks.json](https://api.tessaliq.com/.well-known/jwks.json)
- **OIDF conformance plans** — [plan-detail links](https://demo.certification.openid.net/)

## License

MIT — see `LICENSE`.
