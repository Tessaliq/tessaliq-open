// @tessaliq/sdk-web — Core SDK for Tessaliq identity verification.
//
// This entry point is the mdoc AV / attribute-check / facial-estimate path.
// It does NOT import or reference @noir-lang/* — bundlers that only pull this
// entry will never include Barretenberg (~3 MB wasm).
//
// For the zero-knowledge circuit path (Alpha), import `TessaliqZk` from
// `@tessaliq/sdk-web/zk`. See #71 and #73 for context.

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
  protected config: Required<Pick<TessaliqConfig, 'apiKey' | 'baseUrl'>> & TessaliqConfig
  protected state: TessaliqState = 'idle'

  protected constructor(config: TessaliqConfig) {
    this.config = {
      baseUrl: 'http://localhost:3000',
      ...config,
    }
  }

  static init(config: TessaliqConfig): Tessaliq {
    if (!config.apiKey) throw new Error('Tessaliq: apiKey is required')
    return new Tessaliq(config)
  }

  protected setState(state: TessaliqState) {
    this.state = state
    this.config.onStateChange?.(state)
  }

  getState(): TessaliqState {
    return this.state
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
    const policy = options.policy ?? 'av_age_18_plus'

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
  //
  // Supports two protocols declared in parallel:
  //   - `openid4vp`        — Chrome 128+, carries the OID4VP envelope + DCQL
  //   - `org.iso.mdoc`     — Safari 26+ (iOS 26), raw mdoc ISO 18013-5/7 path,
  //                          no OID4VP wrapper; Safari will not select openid4vp.
  //
  // The browser picks whichever protocol the user's wallet supports, then
  // returns a credential object whose `.protocol` identifies which path was
  // taken. We normalize the response to a credential string that the Tessaliq
  // verifier can accept on /v1/openid4vp/response (it auto-detects
  // SD-JWT-VC vs mdoc CBOR via `isMdocCredential`).
  protected async requestViaDigitalCredentials(requestUri: string): Promise<string | null> {
    try {
      const credential = await navigator.credentials.get({
        // DC API types are not yet in the TypeScript lib
        digital: {
          requests: [
            {
              protocol: 'openid4vp',
              data: { request_uri: requestUri },
            },
            {
              // Safari 26+ / iOS 26 path — raw mdoc, no OID4VP envelope.
              // The `request_uri` here points to a resource the wallet fetches
              // and interprets as an ISO 18013-7 Annex C RequestObject; the
              // verifier JAR already contains the DCQL query so the wallet can
              // satisfy the request in either protocol negotiation.
              protocol: 'org.iso.mdoc',
              data: { request_uri: requestUri },
            },
          ],
        },
      } as any)

      if (!credential) return null

      // DC API response type is not yet in the TypeScript lib
      const rawData = (credential as any).data ?? (credential as any).response

      // Raw mdoc path: the response is a base64url-encoded DeviceResponse
      // (CBOR). Tessaliq's /v1/openid4vp/response handler auto-detects this
      // via isMdocCredential() and dispatches to the mdoc verifier.
      if (typeof rawData === 'string') return rawData

      // OID4VP / DCQL path: { "<credential_id>": "<presentation>" }
      // We take the first value — the verifier handles the dict at its
      // vp_token entry point anyway.
      if (rawData && typeof rawData === 'object') {
        const values = Object.values(rawData)
        if (values.length > 0 && typeof values[0] === 'string') return values[0] as string
      }

      return null
    } catch {
      return null
    }
  }

  // Fallback: open deep link for wallet interaction
  // Returns a promise that resolves when the server receives the credential
  protected async requestViaDeepLink(sessionId: string, deepLink: string): Promise<CredentialResult> {
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
  protected async submitCredentialToServer(
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

  // Facial age estimation verification
  // The selfie is captured and processed client-side by the provider SDK (Didit/Yoti).
  // Tessaliq never receives the image — only the numeric result.
  async verifyWithFace(options: FacialVerifyOptions = {}): Promise<VerifyResult> {
    // Facial estimate uses age_* policies (they carry min_age in publicParams
    // and declare facial_estimate in supportedMethods). av_age_* policies are
    // mdoc wallet-only. The /facial endpoint itself is not ZK-gated.
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
  protected async getFacialEstimate(provider: string): Promise<FacialEstimateResult> {
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
    this.setState('idle')
  }
}

export default Tessaliq
