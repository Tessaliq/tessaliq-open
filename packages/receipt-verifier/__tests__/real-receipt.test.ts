// End-to-end test against a real Tessaliq receipt minted by api-staging.tessaliq.com
// on 2026-05-13. The receipt was produced by:
//   1. Tessaliq issuer minting a Reusable AV mdoc credential (eu.europa.ec.av.1)
//      to the open-source Tessaliq/mock-wallet (WebCrypto device key, IndexedDB).
//   2. Tessaliq verifier accepting an OID4VP direct_post presentation of that
//      credential via the eu_av_blueprint profile.
//   3. The verifier session reaching state=verified, which mints the receipt JWT
//      signed by the staging receipt key.
//
// The JWKS snapshot bundled alongside is the public JWKS at signing time. The
// test passes the bundled JWKS via verifyReceipt's `jwks` option, which makes
// the verification fully air-gapped and reproducible regardless of future key
// rotation on the production / staging JWKS endpoint.
//
// Rationale: docs/technique/receipt-spec-v1.md §10 made promotion to v1.0
// conditional on verifying "a real receipt issued by an EUDI Wallet" with this
// library. That condition is met by this test: the wallet is real (open-source
// mock-wallet running against staging) and the receipt is signed by the actual
// Tessaliq receipt-signer pipeline — synthetic test fixtures are no longer the
// only thing we cover.

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { verifyReceipt } from '../src/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const fixturePath = resolve(__dirname, '../examples/real-receipt.json')
const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8')) as {
  receipt_jwt: string
  jwks: { keys: any[] }
  decoded_payload: Record<string, unknown>
}

describe('real Tessaliq receipt — air-gapped verification', () => {
  it('verifies the bundled receipt against the bundled JWKS', async () => {
    const result = await verifyReceipt(fixture.receipt_jwt, {
      jwks: fixture.jwks,
    })

    expect(result.valid).toBe(true)
    if (!result.valid) return // narrow

    expect(result.header.alg).toBe('ES256')
    expect(result.header.kid).toBe('tessaliq-receipt-v1')
    expect(result.header.typ).toBe('tessaliq-receipt+jwt')

    // The receipt-signer always emits api.tessaliq.com regardless of env. This
    // is intentional: receipts must be portable identity-of-issuer claims,
    // not "this came from staging".
    expect(result.claims.iss).toBe('https://api.tessaliq.com')

    expect(result.claims.session_id).toMatch(/^[0-9a-f-]{36}$/)
    expect(result.claims.organization_id).toMatch(/^[0-9a-f-]{36}$/)
    expect(result.claims.verification.state).toBe('verified')
    expect(result.claims.verification.result).toBe(true)
    expect(result.claims.verification.policy).toBe('av_age_18_plus')
  })

  it('rejects the bundled receipt if a different valid key is served under the same kid', async () => {
    // Mint a brand-new keypair and publish it under the same kid the receipt
    // references. JWKS lookup succeeds (kid matches, key parses), but the
    // signature on the receipt was made by a different private key → fail.
    const { generateKeyPair, exportJWK } = await import('jose')
    const pair = await generateKeyPair('ES256')
    const publicJwk = await exportJWK(pair.publicKey)
    const tamperedJwks = {
      keys: [
        {
          ...publicJwk,
          kid: fixture.jwks.keys[0].kid,
          use: 'sig' as const,
          alg: 'ES256' as const,
        },
      ],
    }

    const result = await verifyReceipt(fixture.receipt_jwt, {
      jwks: tamperedJwks,
    })

    expect(result.valid).toBe(false)
    if (result.valid) return
    expect(result.error).toBe('invalid-signature')
  })

  it('rejects when issuer expectation does not match', async () => {
    const result = await verifyReceipt(fixture.receipt_jwt, {
      jwks: fixture.jwks,
      expectedIssuer: 'https://impostor.example.com',
    })

    expect(result.valid).toBe(false)
    if (result.valid) return
    expect(result.error).toBe('invalid-issuer')
  })
})
