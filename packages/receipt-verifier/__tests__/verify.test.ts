// Tests for @tessaliq/receipt-verifier.
// These tests mirror the invariants documented in
// docs/technique/receipt-spec-v1.md §8 "Garanties apportées par le receipt".

import { describe, it, expect, beforeAll } from 'vitest'
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose'
import { verifyReceipt, type TessaliqReceiptClaims } from '../src/index.js'

const KEY_ID = 'tessaliq-receipt-v1'
const ISSUER = 'https://api.tessaliq.com'
const TYP = 'tessaliq-receipt+jwt'

interface TestKeys {
  privateKey: CryptoKey
  jwk: JWK
}

let keys: TestKeys

beforeAll(async () => {
  const pair = await generateKeyPair('ES256')
  const publicJwk = await exportJWK(pair.publicKey)
  keys = {
    privateKey: pair.privateKey as unknown as CryptoKey,
    jwk: { ...publicJwk, kid: KEY_ID, use: 'sig', alg: 'ES256' },
  }
})

function samplePayload(overrides: Partial<TessaliqReceiptClaims> = {}): Record<string, unknown> {
  const session = '550e8400-e29b-41d4-a716-446655440000'
  return {
    session_id: session,
    organization_id: '7f3d2e1a-8b4c-4d5e-9f6a-1b2c3d4e5f6a',
    verification: {
      policy: 'av_age_18_plus',
      policy_version: 1,
      result: true,
      state: 'verified',
      created_at: '2026-04-20T12:00:00.000Z',
      completed_at: '2026-04-20T12:00:02.145Z',
      assurance_level: 'unknown',
      ...(overrides.verification ?? {}),
    },
    proof: overrides.proof === undefined ? null : overrides.proof,
    ...(overrides.dpv ? { dpv: overrides.dpv } : {}),
  }
}

async function sign(payload: Record<string, unknown>, opts: { iss?: string; typ?: string; alg?: 'ES256' } = {}): Promise<string> {
  const sig = new SignJWT(payload)
    .setProtectedHeader({ alg: opts.alg ?? 'ES256', kid: KEY_ID, typ: opts.typ ?? TYP })
    .setIssuer(opts.iss ?? ISSUER)
    .setIssuedAt()
    .setJti(payload.session_id as string)
  return sig.sign(keys.privateKey)
}

describe('verifyReceipt', () => {
  it('accepts a valid receipt signed with ES256 and the expected issuer/typ', async () => {
    const jwt = await sign(samplePayload())
    const result = await verifyReceipt(jwt, { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.claims.verification.policy).toBe('av_age_18_plus')
      expect(result.claims.verification.result).toBe(true)
      expect(result.claims.jti).toBe(result.claims.session_id)
      expect(result.header.kid).toBe(KEY_ID)
      expect(result.header.alg).toBe('ES256')
    }
  })

  it('rejects a tampered signature', async () => {
    const jwt = await sign(samplePayload())
    const parts = jwt.split('.')
    const sig = parts[2]
    const tamperedSig = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)
    const tampered = [parts[0], parts[1], tamperedSig].join('.')
    const result = await verifyReceipt(tampered, { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.error).toBe('invalid-signature')
  })

  it('rejects a receipt signed by the wrong issuer', async () => {
    const jwt = await sign(samplePayload(), { iss: 'https://evil.example.com' })
    const result = await verifyReceipt(jwt, { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.error).toBe('invalid-issuer')
  })

  it('accepts a receipt with state "failed" and result false', async () => {
    const jwt = await sign(
      samplePayload({
        verification: {
          policy: 'av_age_18_plus',
          policy_version: 1,
          result: false,
          state: 'failed',
          created_at: '2026-04-20T13:20:00.000Z',
          completed_at: '2026-04-20T13:20:03.412Z',
          assurance_level: 'unknown',
        },
      }),
    )
    const result = await verifyReceipt(jwt, { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.claims.verification.state).toBe('failed')
      expect(result.claims.verification.result).toBe(false)
    }
  })

  it('rejects a receipt with an unknown verification.state value', async () => {
    const jwt = await sign(
      samplePayload({
        verification: {
          policy: 'av_age_18_plus',
          policy_version: 1,
          result: true,
          state: 'wibble' as 'verified',
          created_at: '2026-04-20T12:00:00.000Z',
          completed_at: '2026-04-20T12:00:02.145Z',
          assurance_level: 'unknown',
        },
      }),
    )
    const result = await verifyReceipt(jwt, { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.error).toBe('invalid-structure')
  })

  it('rejects a receipt whose jti does not equal session_id', async () => {
    const sig = new SignJWT(samplePayload() as Record<string, unknown>)
      .setProtectedHeader({ alg: 'ES256', kid: KEY_ID, typ: TYP })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setJti('mismatched-jti')
    const jwt = await sig.sign(keys.privateKey)
    const result = await verifyReceipt(jwt, { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(false)
    if (!result.valid) expect(result.error).toBe('invalid-structure')
  })

  it('accepts all four assurance_level values', async () => {
    for (const loa of ['low', 'substantial', 'high', 'unknown'] as const) {
      const jwt = await sign(
        samplePayload({
          verification: {
            policy: 'av_age_18_plus',
            policy_version: 1,
            result: true,
            state: 'verified',
            created_at: '2026-04-20T12:00:00.000Z',
            completed_at: '2026-04-20T12:00:02.145Z',
            assurance_level: loa,
          },
        }),
      )
      const result = await verifyReceipt(jwt, { jwks: { keys: [keys.jwk] } })
      expect(result.valid, `loa=${loa} should verify`).toBe(true)
      if (result.valid) expect(result.claims.verification.assurance_level).toBe(loa)
    }
  })

  it('accepts a receipt with a proof object', async () => {
    const jwt = await sign(
      samplePayload({
        proof: {
          circuit_id: 'age_range_v1',
          circuit_version: '0.36.0',
          proof_hash: 'a'.repeat(64),
          verified_at: '2026-04-20T12:00:01.820Z',
        },
      }),
    )
    const result = await verifyReceipt(jwt, { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(true)
    if (result.valid) expect(result.claims.proof?.circuit_id).toBe('age_range_v1')
  })

  it('rejects a random string that is not a JWT', async () => {
    const result = await verifyReceipt('not-a-jwt', { jwks: { keys: [keys.jwk] } })
    expect(result.valid).toBe(false)
  })
})
