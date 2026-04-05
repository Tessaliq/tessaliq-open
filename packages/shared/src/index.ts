// @tessaliq/shared — Types and constants shared across packages

export const VERSION = '0.1.0'

// Verification methods
export type VerificationMethod =
  | 'eudi_wallet'
  | 'nfc_document'
  | 'facial_estimate'
  | 'auto'

export const VERIFICATION_METHODS: VerificationMethod[] = [
  'eudi_wallet',
  'nfc_document',
  'facial_estimate',
  'auto',
]

// Verification session states (FSM)
export type SessionState =
  | 'created'
  | 'wallet_requested'
  | 'presentation_received'
  | 'proving'
  | 'verified'
  | 'failed'
  | 'expired'

// API error codes
export type ErrorCode =
  | 'invalid_api_key'
  | 'rate_limited'
  | 'session_not_found'
  | 'session_expired'
  | 'proof_invalid'
  | 'credential_invalid'
  | 'internal_error'

export interface ApiError {
  code: ErrorCode
  message: string
  status: number
}

export interface VerificationSession {
  id: string
  state: SessionState
  policy_id: string
  method: VerificationMethod
  created_at: string
  expires_at: string
  result?: boolean
}

export interface VerificationResult {
  session_id: string
  verified: boolean
  proof_hash?: string
  completed_at: string
}

export interface VerificationReceipt {
  receipt_token: string
  receipt_fingerprint: string
  jwks_url: string
}

export interface ReceiptVerificationResult {
  valid: boolean
  registered?: boolean
  receipt?: {
    session_id: string
    verification: {
      policy: string
      policy_version: number
      result: boolean
      state: string
      created_at: string
      completed_at: string | null
    }
    proof: {
      circuit_id: string
      circuit_version: string
      proof_hash: string
      verified_at: string
    } | null
  }
}
