// Verify a Tessaliq receipt from a Node.js script.
//
// This example does two things:
//   1. Generates a local test key + signs a sample payload, then verifies it
//      against the local JWKS — useful to exercise the flow without a real
//      receipt or network access.
//   2. Shows the production pattern — fetch the Tessaliq JWKS and verify a
//      real receipt loaded from a file.
//
// Run:
//   pnpm -F @tessaliq/receipt-verifier build    # build the lib
//   node examples/receipt-verifier/node-example.mjs
//
// Node.js >= 20, jose >= 5.

import { readFileSync } from 'node:fs'
import { jwtVerify, createRemoteJWKSet, SignJWT, generateKeyPair, exportJWK } from 'jose'

const KID = 'tessaliq-receipt-v1'
const ISS = 'https://api.tessaliq.com'
const TYP = 'tessaliq-receipt+jwt'

// ----- 1. Local round-trip: sign then verify with a freshly generated key -----

async function localRoundTrip() {
  console.log('--- Local round-trip (no network) ---')
  const { publicKey, privateKey } = await generateKeyPair('ES256')
  const publicJwk = await exportJWK(publicKey)
  const jwks = { keys: [{ ...publicJwk, kid: KID, use: 'sig', alg: 'ES256' }] }

  const samplePayload = {
    session_id: '550e8400-e29b-41d4-a716-446655440000',
    organization_id: '7f3d2e1a-8b4c-4d5e-9f6a-1b2c3d4e5f6a',
    verification: {
      policy: 'av_age_18_plus',
      policy_version: 1,
      result: true,
      state: 'verified',
      created_at: '2026-04-20T12:00:00.000Z',
      completed_at: '2026-04-20T12:00:02.145Z',
      assurance_level: 'unknown',
    },
    proof: null,
  }

  const jwt = await new SignJWT(samplePayload)
    .setProtectedHeader({ alg: 'ES256', kid: KID, typ: TYP })
    .setIssuer(ISS)
    .setIssuedAt()
    .setJti(samplePayload.session_id)
    .sign(privateKey)

  console.log('Signed JWT (truncated):', jwt.slice(0, 80) + '…')

  // Import the verify path — prefer the bundled lib if available, else jose directly.
  let verifyResult
  try {
    const { verifyReceipt } = await import('../../packages/receipt-verifier/dist/index.js')
    verifyResult = await verifyReceipt(jwt, { jwks })
  } catch {
    // Fallback: manual jose call if the lib isn't built.
    const { jwtVerify: jv } = await import('jose')
    const res = await jv(jwt, { keys: jwks.keys }, { issuer: ISS, algorithms: ['ES256'], typ: TYP })
    verifyResult = { valid: true, claims: res.payload, header: res.protectedHeader }
  }

  if (verifyResult.valid) {
    console.log('✓ verified locally')
    console.log('  policy :', verifyResult.claims.verification.policy)
    console.log('  result :', verifyResult.claims.verification.result)
  } else {
    console.error('✗ local verify failed:', verifyResult.error, verifyResult.message)
    process.exitCode = 1
  }
}

// ----- 2. Production pattern: fetch Tessaliq JWKS, verify a real receipt from disk -----

async function fromFile(path) {
  console.log(`\n--- Verifying receipt from ${path} against ${ISS} ---`)
  const jwt = readFileSync(path, 'utf-8').trim()

  const jwks = createRemoteJWKSet(new URL(`${ISS}/.well-known/jwks.json`))
  try {
    const { payload, protectedHeader } = await jwtVerify(jwt, jwks, {
      issuer: ISS,
      algorithms: ['ES256'],
      typ: TYP,
    })
    console.log('✓ valid')
    console.log('  kid    :', protectedHeader.kid)
    console.log('  policy :', payload.verification.policy)
    console.log('  result :', payload.verification.result)
    console.log('  sess   :', payload.session_id)
  } catch (err) {
    console.error('✗ verification failed:', err.code ?? err.name ?? err.message)
    process.exitCode = 1
  }
}

// ----- main -----

await localRoundTrip()

const arg = process.argv[2]
if (arg && arg !== '--skip-file') {
  await fromFile(arg)
} else {
  console.log('\n(Skip file verification — pass a receipt file path as an argument to run it.)')
}
