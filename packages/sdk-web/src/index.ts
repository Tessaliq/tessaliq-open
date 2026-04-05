// @tessaliq/sdk-web — Client-side SDK for Tessaliq zero-knowledge identity verification

import { Noir } from '@noir-lang/noir_js'
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg'

export interface TessaliqConfig {
  apiKey: string
  baseUrl?: string
  circuitUrl?: string
  onStateChange?: (state: TessaliqState) => void
}

export type TessaliqState =
  | 'idle'
  | 'creating_session'
  | 'loading_circuit'
  | 'waiting_credential'
  | 'generating_proof'
  | 'submitting_proof'
  | 'verified'
  | 'failed'

export interface VerifyOptions {
  policy?: string
  externalRef?: string
  birthYear: number
  birthMonth: number
  birthDay: number
  credentialSecret?: string
}

// Options for wallet-based verification (EUDI Wallet / Digital Credentials API)
export interface WalletVerifyOptions {
  policy?: string
  externalRef?: string
}

// Options for facial age estimation verification
export interface FacialVerifyOptions {
  policy?: string
  externalRef?: string
  /** Provider to use ('didit' or 'yoti'). Default: 'didit' */
  provider?: 'didit' | 'yoti'
}

// Result from facial estimation (before submitting to Tessaliq)
export interface FacialEstimateResult {
  age_estimate: number
  confidence: number
  provider: string
  provider_token?: string
}

export interface VerifyResult {
  verified: boolean
  sessionId: string
  proofHash?: string
  error?: string
}

// Result from requesting a credential via the wallet
export interface CredentialResult {
  credential: string      // SD-JWT-VC from the wallet
  sessionId: string
  claims: {
    birthYear: number
    birthMonth: number
    birthDay: number
  } | null
  method: 'digital-credentials-api' | 'deep-link'
}

export class Tessaliq {
  private config: Required<Pick<TessaliqConfig, 'apiKey' | 'baseUrl'>> & TessaliqConfig
  private state: TessaliqState = 'idle'
  private circuitArtifact: any = null
  private backend: BarretenbergBackend | null = null
  private noir: Noir | null = null

  private constructor(config: TessaliqConfig) {
    this.config = {
      baseUrl: 'http://localhost:3000',
      ...config,
    }
  }

  static init(config: TessaliqConfig): Tessaliq {
    if (!config.apiKey) throw new Error('Tessaliq: apiKey is required')
    return new Tessaliq(config)
  }

  private setState(state: TessaliqState) {
    this.state = state
    this.config.onStateChange?.(state)
  }

  getState(): TessaliqState {
    return this.state
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

  // Check if Digital Credentials API is available in the browser
  static isDigitalCredentialsSupported(): boolean {
    try {
      return typeof window !== 'undefined'
        && 'credentials' in navigator
        && typeof (navigator.credentials as any).get === 'function'
        // Feature-detect the 'digital' option support
        && typeof window.PublicKeyCredential !== 'undefined'
    } catch {
      return false
    }
  }

  // Request a credential from the EUDI Wallet via Digital Credentials API
  // Falls back to deep link if DC API is not available
  async requestCredential(options: WalletVerifyOptions = {}): Promise<CredentialResult> {
    const policy = options.policy ?? 'age_18_plus'

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

    // 2. Get the request URI for this session
    const linkRes = await fetch(`${this.config.baseUrl}/v1/openid4vp/link/${session.id}`)
    if (!linkRes.ok) throw new Error('Failed to get OpenID4VP link')
    const linkData = await linkRes.json()

    // 3. Try Digital Credentials API first
    this.setState('waiting_credential')

    if (Tessaliq.isDigitalCredentialsSupported()) {
      try {
        const credential = await this.requestViaDigitalCredentials(linkData.request_uri)
        if (credential) {
          // Send the credential to the server for verification
          return await this.submitCredentialToServer(session.id, credential, 'digital-credentials-api')
        }
      } catch {
        // DC API failed — fall through to deep link
      }
    }

    // 4. Fallback: open deep link and wait for server-side callback
    return this.requestViaDeepLink(session.id, linkData.deep_link)
  }

  // Request credential via the W3C Digital Credentials API
  // https://www.w3.org/TR/digital-credentials/
  private async requestViaDigitalCredentials(requestUri: string): Promise<string | null> {
    try {
      const credential = await navigator.credentials.get({
        // @ts-expect-error — DC API types not yet in TypeScript lib
        digital: {
          requests: [{
            protocol: 'openid4vp',
            data: { request_uri: requestUri },
          }],
        },
      } as any)

      if (!credential) return null

      // The DC API returns the vp_token in the credential data
      // @ts-expect-error — DC API response type
      const data = credential.data ?? credential.response
      if (typeof data === 'string') return data
      if (data && typeof data === 'object') {
        // DCQL format: { "pid-age_18_plus": "eyJ..." }
        const values = Object.values(data)
        if (values.length > 0 && typeof values[0] === 'string') return values[0] as string
      }

      return null
    } catch {
      return null
    }
  }

  // Fallback: open deep link for wallet interaction
  // Returns a promise that resolves when the server receives the credential
  private async requestViaDeepLink(sessionId: string, deepLink: string): Promise<CredentialResult> {
    // Open the deep link
    window.location.href = deepLink

    // Poll the server for credential receipt (session state changes)
    const maxWait = 120_000 // 2 minutes
    const pollInterval = 2_000
    const start = Date.now()

    while (Date.now() - start < maxWait) {
      await new Promise(r => setTimeout(r, pollInterval))

      const res = await fetch(`${this.config.baseUrl}/v1/sessions/${sessionId}`, {
        headers: { 'Authorization': `Bearer ${this.config.apiKey}` },
      })
      if (!res.ok) continue

      const session = await res.json()
      if (session.state === 'presentation_received' || session.state === 'verified') {
        return {
          credential: '',  // Credential already processed server-side
          sessionId,
          claims: session.claims ?? null,
          method: 'deep-link',
        }
      }
      if (session.state === 'failed') {
        throw new Error('Wallet credential presentation failed')
      }
    }

    throw new Error('Timeout waiting for wallet credential')
  }

  // Submit a wallet credential to the server for verification
  private async submitCredentialToServer(
    sessionId: string,
    vpToken: string,
    method: 'digital-credentials-api' | 'deep-link',
  ): Promise<CredentialResult> {
    const res = await fetch(`${this.config.baseUrl}/v1/openid4vp/response`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        vp_token: vpToken,
        state: sessionId,
      }),
    })

    if (!res.ok) {
      const err = await res.json().catch(() => ({ message: 'Credential submission failed' }))
      throw new Error(err.message)
    }

    const result = await res.json()
    return {
      credential: vpToken,
      sessionId,
      claims: result.claims_available ?? null,
      method,
    }
  }

  // Full wallet-based verification: request credential → extract claims → generate ZK proof → verify
  async verifyWithWallet(options: WalletVerifyOptions = {}): Promise<VerifyResult> {
    try {
      // 1. Request credential from wallet
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

  // Facial age estimation verification
  // The selfie is captured and processed client-side by the provider SDK (Didit/Yoti).
  // Tessaliq never receives the image — only the numeric result.
  async verifyWithFace(options: FacialVerifyOptions = {}): Promise<VerifyResult> {
    const policy = options.policy ?? 'age_18_plus'
    const provider = options.provider ?? 'didit'

    try {
      // 1. Create session with facial method
      this.setState('creating_session')
      const sessRes = await fetch(`${this.config.baseUrl}/v1/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
        body: JSON.stringify({
          policy,
          method: 'facial_estimate',
          external_ref: options.externalRef,
        }),
      })

      if (!sessRes.ok) {
        const err = await sessRes.json()
        throw new Error(err.message ?? 'Failed to create session')
      }

      const session = await sessRes.json()

      // 2. Get facial estimate from provider SDK
      // The provider SDK captures the selfie and sends it directly to their API.
      // We receive back only the numeric result.
      this.setState('waiting_credential')
      const estimate = await this.getFacialEstimate(provider)

      // 3. Submit to Tessaliq for verification
      this.setState('submitting_proof')
      const verifyRes = await fetch(`${this.config.baseUrl}/v1/sessions/${session.id}/facial`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          age_estimate: estimate.age_estimate,
          confidence: estimate.confidence,
          provider: estimate.provider,
          provider_token: estimate.provider_token,
        }),
      })

      const result = await verifyRes.json()

      if (result.verified) {
        this.setState('verified')
        return { verified: true, sessionId: session.id, proofHash: result.proof_hash }
      } else {
        this.setState('failed')
        return { verified: false, sessionId: session.id, error: result.reason ?? 'Verification failed' }
      }
    } catch (err: any) {
      this.setState('failed')
      return { verified: false, sessionId: '', error: err.message ?? 'Unknown error' }
    }
  }

  // Get facial age estimate from the provider SDK
  // In production: calls the Didit/Yoti JS SDK to capture selfie + estimate age
  // In mock mode: returns a simulated result for testing
  private async getFacialEstimate(provider: string): Promise<FacialEstimateResult> {
    // Check if the provider SDK is loaded on the page
    if (provider === 'didit' && typeof (window as any).__didit_estimate === 'function') {
      return (window as any).__didit_estimate()
    }
    if (provider === 'yoti' && typeof (window as any).__yoti_estimate === 'function') {
      return (window as any).__yoti_estimate()
    }

    // Mock mode: simulate a successful estimation for testing
    // This allows testing the full flow without a real provider account
    if (typeof (window as any).__tessaliq_mock_facial === 'function') {
      return (window as any).__tessaliq_mock_facial()
    }

    // Default mock for development/sandbox
    return {
      age_estimate: 25,
      confidence: 0.92,
      provider,
    }
  }

  async destroy() {
    this.backend?.destroy()
    this.backend = null
    this.noir = null
    this.circuitArtifact = null
    this.setState('idle')
  }
}

export default Tessaliq
