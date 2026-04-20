// @tessaliq/receipt-verifier — verify Tessaliq receipt JWTs offline.
// Spec: docs/technique/receipt-spec-v1.md
// License: MIT

import {
  jwtVerify,
  createRemoteJWKSet,
  createLocalJWKSet,
  type JWTPayload,
  type JWTVerifyResult,
  type JSONWebKeySet,
  errors,
} from 'jose'

/**
 * Shape of the application-specific claims carried by a Tessaliq receipt.
 * Standard JWT claims (iss, iat, jti) are also present on the decoded payload
 * and are checked by the verifier.
 *
 * See docs/technique/receipt-spec-v1.md §3 for the authoritative definition.
 */
export interface TessaliqReceiptClaims {
  iss: string
  iat: number
  jti: string
  session_id: string
  organization_id: string
  verification: {
    policy: string
    policy_version: number
    result: boolean
    state: 'verified' | 'failed'
    created_at: string
    completed_at: string | null
    assurance_level: 'low' | 'substantial' | 'high' | 'unknown'
  }
  proof: {
    circuit_id: string
    circuit_version: string
    proof_hash: string
    verified_at: string
  } | null
  dpv?: Record<string, unknown>
}

export interface VerifyOptions {
  /**
   * URL of the Tessaliq JWKS endpoint.
   * Defaults to 'https://api.tessaliq.com/.well-known/jwks.json'.
   * Override for staging / custom deployments.
   */
  jwksUrl?: string
  /**
   * Pre-fetched JWKS. Mutually exclusive with jwksUrl.
   * Useful for fully offline verification (e.g. air-gapped audit).
   */
  jwks?: JSONWebKeySet
  /**
   * Expected issuer. Defaults to 'https://api.tessaliq.com'.
   * Override for staging.
   */
  expectedIssuer?: string
}

export type VerifyResult =
  | {
      valid: true
      claims: TessaliqReceiptClaims
      header: { alg: string; kid: string; typ?: string }
    }
  | {
      valid: false
      error:
        | 'invalid-signature'
        | 'invalid-algorithm'
        | 'invalid-issuer'
        | 'invalid-structure'
        | 'jwks-fetch-failed'
        | 'unknown'
      message: string
    }

const DEFAULT_JWKS_URL = 'https://api.tessaliq.com/.well-known/jwks.json'
const DEFAULT_ISSUER = 'https://api.tessaliq.com'
const EXPECTED_TYP = 'tessaliq-receipt+jwt'
const EXPECTED_ALG = 'ES256'

/**
 * Verify a Tessaliq receipt JWT.
 *
 * The verification is fully cryptographic and does not require access to the
 * Tessaliq API (only the public JWKS endpoint is fetched, and you can skip
 * that too by pre-fetching the JWKS and passing it via options.jwks).
 *
 * A successful result proves:
 *  - The JWT was signed with the Tessaliq private key whose public counterpart
 *    is currently published at the JWKS endpoint (kid: tessaliq-receipt-v1).
 *  - The claims have not been tampered with since signature.
 *
 * See docs/technique/receipt-spec-v1.md §8 for the full scope of guarantees.
 */
export async function verifyReceipt(
  jwt: string,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const jwksUrl = options.jwksUrl ?? DEFAULT_JWKS_URL
  const expectedIssuer = options.expectedIssuer ?? DEFAULT_ISSUER

  let keySet
  try {
    keySet = options.jwks
      ? createLocalJWKSet(options.jwks)
      : createRemoteJWKSet(new URL(jwksUrl))
  } catch (err) {
    return {
      valid: false,
      error: 'jwks-fetch-failed',
      message: err instanceof Error ? err.message : String(err),
    }
  }

  let result: JWTVerifyResult<JWTPayload>
  try {
    result = await jwtVerify(jwt, keySet, {
      issuer: expectedIssuer,
      algorithms: [EXPECTED_ALG],
      typ: EXPECTED_TYP,
    })
  } catch (err) {
    if (err instanceof errors.JWSSignatureVerificationFailed) {
      return {
        valid: false,
        error: 'invalid-signature',
        message: 'Signature verification failed',
      }
    }
    if (err instanceof errors.JOSEAlgNotAllowed) {
      return {
        valid: false,
        error: 'invalid-algorithm',
        message: `Algorithm not allowed — expected ${EXPECTED_ALG}`,
      }
    }
    if (err instanceof errors.JWTClaimValidationFailed && err.claim === 'iss') {
      return {
        valid: false,
        error: 'invalid-issuer',
        message: `Issuer mismatch — expected ${expectedIssuer}`,
      }
    }
    return {
      valid: false,
      error: 'unknown',
      message: err instanceof Error ? err.message : String(err),
    }
  }

  const payload = result.payload as unknown as TessaliqReceiptClaims
  const header = result.protectedHeader as { alg: string; kid: string; typ?: string }

  const structureCheck = checkClaimStructure(payload)
  if (structureCheck) {
    return {
      valid: false,
      error: 'invalid-structure',
      message: structureCheck,
    }
  }

  return {
    valid: true,
    claims: payload,
    header,
  }
}

/**
 * Validate the application-specific shape of a receipt payload.
 * Returns null if valid, or an error message describing the first missing/bad field.
 */
function checkClaimStructure(p: TessaliqReceiptClaims): string | null {
  if (typeof p.session_id !== 'string' || !p.session_id) return 'missing session_id'
  if (typeof p.organization_id !== 'string' || !p.organization_id) return 'missing organization_id'
  if (p.jti !== p.session_id) return 'jti must equal session_id'
  const v = p.verification
  if (!v) return 'missing verification object'
  if (typeof v.policy !== 'string' || !v.policy) return 'missing verification.policy'
  if (typeof v.policy_version !== 'number') return 'missing verification.policy_version'
  if (typeof v.result !== 'boolean') return 'missing verification.result'
  if (v.state !== 'verified' && v.state !== 'failed') return 'verification.state must be "verified" or "failed"'
  if (typeof v.created_at !== 'string') return 'missing verification.created_at'
  if (v.completed_at !== null && typeof v.completed_at !== 'string') return 'verification.completed_at must be string or null'
  const loa = v.assurance_level
  if (loa !== 'low' && loa !== 'substantial' && loa !== 'high' && loa !== 'unknown') {
    return 'verification.assurance_level must be one of low | substantial | high | unknown'
  }
  if (p.proof !== null) {
    const pf = p.proof
    if (typeof pf.circuit_id !== 'string') return 'missing proof.circuit_id'
    if (typeof pf.circuit_version !== 'string') return 'missing proof.circuit_version'
    if (typeof pf.proof_hash !== 'string') return 'missing proof.proof_hash'
    if (typeof pf.verified_at !== 'string') return 'missing proof.verified_at'
  }
  return null
}
