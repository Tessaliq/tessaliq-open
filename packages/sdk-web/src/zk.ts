// @tessaliq/sdk-web/zk — Zero-knowledge verification path (Alpha).
//
// This entry point pulls @noir-lang/noir_js and @noir-lang/backend_barretenberg.
// Import it only if your integration actually needs ZK proofs. The core SDK
// (`@tessaliq/sdk-web`) is enough for mdoc AV, facial estimation and wallet
// credential flows.
//
// Status: ALPHA. The underlying @aztec/bb.js 0.58.0 is affected by a critical
// vulnerability disclosed on 2026-03-17 (issue #67). Do not use this path in
// a critical verification flow until the Noir 1.0 migration (#23) lands.

import { Noir } from '@noir-lang/noir_js'
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg'
import {
  Tessaliq,
  type TessaliqConfig,
  type VerifyOptions,
  type VerifyResult,
  type WalletVerifyOptions,
} from './index'

/**
 * Inputs for a one-shot age proof generation.
 * The nonce is truncated to 62 hex chars (248 bits) to fit the BN254 field.
 */
export interface AgeProofInputs {
  birthYear: number
  birthMonth: number
  birthDay: number
  /** Hex string, will be passed to the circuit as-is (must fit the BN254 field) */
  credentialHashPreimage: string
  /** Minimum age threshold (18, 21, etc) */
  minAge: number
  /** Session nonce (hex, with or without 0x prefix). Will be truncated to 62 chars. */
  nonce: string
  /** Optional current date override, defaults to new Date() */
  currentDate?: Date
}

export interface GeneratedProof {
  proof: Uint8Array
  publicInputs: string[]
}

/**
 * Generate a zero-knowledge age proof against the Tessaliq circuit.
 * Loads the circuit artifact from the given URL, instantiates a fresh
 * Barretenberg backend, runs the proof, and destroys the backend.
 *
 * Use this helper in UI flows that work against a pre-created session
 * (e.g. the hosted /verify/[id] page). For a full session-creating flow
 * use `TessaliqZk.init(...).verify(...)`.
 */
export async function generateAgeProof(
  circuitUrl: string,
  inputs: AgeProofInputs,
): Promise<GeneratedProof> {
  const res = await fetch(circuitUrl)
  if (!res.ok) throw new Error(`Failed to load circuit: ${res.status}`)
  const circuit = await res.json()
  const backend = new BarretenbergBackend(circuit)
  const noir = new Noir(circuit)
  try {
    const now = inputs.currentDate ?? new Date()
    const truncatedNonce = '0x' + inputs.nonce.replace(/^0x/, '').slice(0, 62)
    const { witness } = await noir.execute({
      birth_year: String(inputs.birthYear),
      birth_month: String(inputs.birthMonth),
      birth_day: String(inputs.birthDay),
      credential_hash_preimage: inputs.credentialHashPreimage,
      current_year: String(now.getFullYear()),
      current_month: String(now.getMonth() + 1),
      current_day: String(now.getDate()),
      min_age: String(inputs.minAge),
      nonce: truncatedNonce,
    })
    const proof = await backend.generateProof(witness)
    return {
      proof: proof.proof,
      publicInputs: proof.publicInputs,
    }
  } finally {
    backend.destroy()
  }
}

export class TessaliqZk extends Tessaliq {
  private circuitArtifact: any = null
  private backend: BarretenbergBackend | null = null
  private noir: Noir | null = null

  static override init(config: TessaliqConfig): TessaliqZk {
    if (!config.apiKey) throw new Error('Tessaliq: apiKey is required')
    return new TessaliqZk(config)
  }

  private async loadCircuit() {
    if (this.circuitArtifact) return

    const url = this.config.circuitUrl ?? `${this.config.baseUrl}/circuits/age_verification.json`
    const res = await fetch(url)
    if (!res.ok) throw new Error(`Failed to load circuit: ${res.status}`)
    this.circuitArtifact = await res.json()
    this.backend = new BarretenbergBackend(this.circuitArtifact)
    this.noir = new Noir(this.circuitArtifact)
  }

  async verify(options: VerifyOptions): Promise<VerifyResult> {
    const policy = options.policy ?? 'age_18_plus'
    const credentialSecret = options.credentialSecret ?? String(Math.floor(Math.random() * 1e15))

    try {
      // 1. Create session
      this.setState('creating_session')
      const sessRes = await fetch(`${this.config.baseUrl}/v1/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
        body: JSON.stringify({
          policy,
          external_ref: options.externalRef,
        }),
      })

      if (!sessRes.ok) {
        const err = await sessRes.json()
        throw new Error(err.message ?? 'Failed to create session')
      }

      const session = await sessRes.json()

      // 2. Load circuit (cached after first load)
      this.setState('loading_circuit')
      await this.loadCircuit()

      // 3. Generate ZK proof
      this.setState('generating_proof')
      const now = new Date()
      const nonce = '0x' + session.nonce.slice(0, 62) // Truncate to fit BN254 field

      const { witness } = await this.noir!.execute({
        birth_year: String(options.birthYear),
        birth_month: String(options.birthMonth),
        birth_day: String(options.birthDay),
        credential_hash_preimage: credentialSecret,
        current_year: String(now.getFullYear()),
        current_month: String(now.getMonth() + 1),
        current_day: String(now.getDate()),
        min_age: '18',
        nonce,
      })

      const proof = await this.backend!.generateProof(witness)

      // 4. Submit proof
      this.setState('submitting_proof')
      const verifyRes = await fetch(`${this.config.baseUrl}/v1/sessions/${session.id}/proof`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proof: Array.from(proof.proof),
          public_inputs: proof.publicInputs,
          nonce: session.nonce,
        }),
      })

      const result = await verifyRes.json()

      if (result.verified) {
        this.setState('verified')
        return {
          verified: true,
          sessionId: session.id,
          proofHash: result.proof_hash,
        }
      } else {
        this.setState('failed')
        return {
          verified: false,
          sessionId: session.id,
          error: 'Proof verification failed',
        }
      }
    } catch (err: any) {
      this.setState('failed')
      return {
        verified: false,
        sessionId: '',
        error: err.message ?? 'Unknown error',
      }
    }
  }

  // Full wallet-based verification: request credential → extract claims → generate ZK proof → verify
  async verifyWithWallet(options: WalletVerifyOptions = {}): Promise<VerifyResult> {
    try {
      // 1. Request credential from wallet (inherited from core)
      const credResult = await this.requestCredential(options)

      if (!credResult.claims) {
        this.setState('failed')
        return { verified: false, sessionId: credResult.sessionId, error: 'No age claims in credential' }
      }

      // 2. Load circuit
      this.setState('loading_circuit')
      await this.loadCircuit()

      // 3. Generate ZK proof from the wallet credential
      this.setState('generating_proof')
      const now = new Date()
      const sessRes = await fetch(`${this.config.baseUrl}/v1/sessions/${credResult.sessionId}`, {
        headers: { 'Authorization': `Bearer ${this.config.apiKey}` },
      })
      const session = await sessRes.json()
      const nonce = '0x' + session.nonce.slice(0, 62)

      // Use credential binding if we have the raw credential
      const credentialBinding = credResult.credential
        ? await this.computeCredentialBinding(credResult.credential)
        : String(Math.floor(Math.random() * 1e15))

      const { witness } = await this.noir!.execute({
        birth_year: String(credResult.claims.birthYear),
        birth_month: String(credResult.claims.birthMonth),
        birth_day: String(credResult.claims.birthDay),
        credential_hash_preimage: credentialBinding,
        current_year: String(now.getFullYear()),
        current_month: String(now.getMonth() + 1),
        current_day: String(now.getDate()),
        min_age: '18',
        nonce,
      })

      const proof = await this.backend!.generateProof(witness)

      // 4. Submit proof
      this.setState('submitting_proof')
      const verifyRes = await fetch(`${this.config.baseUrl}/v1/sessions/${credResult.sessionId}/proof`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proof: Array.from(proof.proof),
          public_inputs: proof.publicInputs,
          nonce: session.nonce,
          credential: credResult.credential || undefined,
        }),
      })

      const result = await verifyRes.json()

      if (result.verified) {
        this.setState('verified')
        return { verified: true, sessionId: credResult.sessionId, proofHash: result.proof_hash }
      } else {
        this.setState('failed')
        return { verified: false, sessionId: credResult.sessionId, error: 'Proof verification failed' }
      }
    } catch (err: any) {
      this.setState('failed')
      return { verified: false, sessionId: '', error: err.message ?? 'Unknown error' }
    }
  }

  // Compute credential binding hash (same logic as server-side computeCredentialBinding)
  private async computeCredentialBinding(sdJwt: string): Promise<string> {
    const issuerJwt = sdJwt.split('~')[0]
    const signature = issuerJwt.split('.')[2]
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(signature))
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')
    return '0x' + hashHex.slice(0, 62) // Truncate to 248 bits for BN254 field
  }

  override async destroy() {
    this.backend?.destroy()
    this.backend = null
    this.noir = null
    this.circuitArtifact = null
    await super.destroy()
  }
}

export default TessaliqZk
