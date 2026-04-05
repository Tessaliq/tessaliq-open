import { describe, it, expect } from 'vitest'
import { parseSdJwt, extractAgeClaimsFromCredential, verifyKeyBindingJwt, base64urlEncode } from '../src/index.ts'

// Build a minimal mock SD-JWT for testing
function buildMockSdJwt(claims: Record<string, any>): string {
  const header = base64urlEncode(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt' }))
  const payload = base64urlEncode(JSON.stringify({
    iss: 'https://test.issuer',
    vct: 'eu.europa.ec.eudi.pid.1',
    iat: Math.floor(Date.now() / 1000),
    _sd: [],
    _sd_alg: 'sha-256',
  }))
  const signature = base64urlEncode('fake-signature')
  const jwt = `${header}.${payload}.${signature}`

  // Build disclosures
  const disclosures = Object.entries(claims).map(([name, value]) => {
    return base64urlEncode(JSON.stringify(['salt123', name, value]))
  })

  return jwt + '~' + disclosures.join('~') + '~'
}

describe('SD-JWT Parser', () => {
  it('parses a basic SD-JWT', () => {
    const sdJwt = buildMockSdJwt({ birth_date: '1995-08-22', given_name: 'Marie' })
    const parsed = parseSdJwt(sdJwt)

    expect(parsed.issuerPayload.iss).toBe('https://test.issuer')
    expect(parsed.issuerPayload.vct).toBe('eu.europa.ec.eudi.pid.1')
    expect(parsed.disclosures).toHaveLength(2)
    expect(parsed.disclosedClaims.birth_date).toBe('1995-08-22')
    expect(parsed.disclosedClaims.given_name).toBe('Marie')
  })

  it('extracts age claims from credential', () => {
    const sdJwt = buildMockSdJwt({ birth_date: '1995-08-22' })
    const parsed = parseSdJwt(sdJwt)
    const claims = extractAgeClaimsFromCredential(parsed)

    expect(claims).not.toBeNull()
    expect(claims!.birthYear).toBe(1995)
    expect(claims!.birthMonth).toBe(8)
    expect(claims!.birthDay).toBe(22)
  })

  it('handles alternative birth date field names', () => {
    const sdJwt = buildMockSdJwt({ birthdate: '2000-01-15' })
    const parsed = parseSdJwt(sdJwt)
    const claims = extractAgeClaimsFromCredential(parsed)

    expect(claims!.birthYear).toBe(2000)
    expect(claims!.birthMonth).toBe(1)
    expect(claims!.birthDay).toBe(15)
  })

  it('returns null when no birth date is present', () => {
    const sdJwt = buildMockSdJwt({ given_name: 'Marie' })
    const parsed = parseSdJwt(sdJwt)
    const claims = extractAgeClaimsFromCredential(parsed)

    expect(claims).toBeNull()
  })

  it('handles selective disclosure (fewer claims)', () => {
    const sdJwt = buildMockSdJwt({
      birth_date: '1990-03-10',
      given_name: 'Jean',
      family_name: 'Martin',
      nationality: 'FR',
    })
    const parsed = parseSdJwt(sdJwt)

    expect(parsed.disclosures).toHaveLength(4)
    expect(parsed.disclosedClaims.nationality).toBe('FR')
  })
})

describe('KB-JWT Verification', () => {
  it('passes when no KB-JWT is present (mock wallet)', async () => {
    const sdJwt = 'eyJhbGci.payload.sig~disclosure1~'
    const result = await verifyKeyBindingJwt(sdJwt, 'nonce123', 'https://api.tessaliq.com')
    expect(result.valid).toBe(true)
  })

  it('rejects KB-JWT with wrong nonce', async () => {
    const kbHeader = base64urlEncode(JSON.stringify({ typ: 'kb+jwt', alg: 'ES256' }))
    const kbPayload = base64urlEncode(JSON.stringify({
      nonce: 'wrong-nonce',
      aud: 'https://api.tessaliq.com',
      iat: Math.floor(Date.now() / 1000),
    }))
    const kbJwt = `${kbHeader}.${kbPayload}.fake-sig`
    const sdJwt = `eyJhbGci.payload.sig~disclosure1~${kbJwt}`

    const result = await verifyKeyBindingJwt(sdJwt, 'correct-nonce', 'https://api.tessaliq.com')
    expect(result.valid).toBe(false)
    expect(result.reason).toContain('Nonce mismatch')
  })

  it('rejects KB-JWT with wrong audience', async () => {
    const kbHeader = base64urlEncode(JSON.stringify({ typ: 'kb+jwt', alg: 'ES256' }))
    const kbPayload = base64urlEncode(JSON.stringify({
      nonce: 'nonce123',
      aud: 'https://evil.com',
      iat: Math.floor(Date.now() / 1000),
    }))
    const kbJwt = `${kbHeader}.${kbPayload}.fake-sig`
    const sdJwt = `eyJhbGci.payload.sig~disclosure1~${kbJwt}`

    const result = await verifyKeyBindingJwt(sdJwt, 'nonce123', 'https://api.tessaliq.com')
    expect(result.valid).toBe(false)
    expect(result.reason).toContain('Audience mismatch')
  })

  it('passes KB-JWT with correct nonce and audience', async () => {
    const kbHeader = base64urlEncode(JSON.stringify({ typ: 'kb+jwt', alg: 'ES256' }))
    const kbPayload = base64urlEncode(JSON.stringify({
      nonce: 'nonce123',
      aud: 'https://api.tessaliq.com',
      iat: Math.floor(Date.now() / 1000),
    }))
    const kbJwt = `${kbHeader}.${kbPayload}.fake-sig`
    const sdJwt = `eyJhbGci.payload.sig~disclosure1~${kbJwt}`

    const result = await verifyKeyBindingJwt(sdJwt, 'nonce123', 'https://api.tessaliq.com')
    expect(result.valid).toBe(true)
  })
})
