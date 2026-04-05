# Age Verification ZK Circuit

A [Noir](https://noir-lang.org/) zero-knowledge circuit that proves a person is at least N years old **without revealing their date of birth**.

## How it works

The prover supplies their date of birth as **private inputs**. The circuit:

1. Validates date ranges (month 1-12, day 1-31, year 1900-now)
2. Computes exact age accounting for whether birthday has passed this year
3. Asserts `age >= min_age`
4. Returns a Pedersen hash binding the credential to the session nonce

The verifier only sees: current date, minimum age threshold, nonce, and the binding hash. **The date of birth never leaves the prover.**

## Inputs

| Input | Visibility | Description |
|-------|-----------|-------------|
| `birth_year` | Private | Year of birth |
| `birth_month` | Private | Month of birth (1-12) |
| `birth_day` | Private | Day of birth (1-31) |
| `credential_hash_preimage` | Private | Credential binding (SHA-256 of JWT signature, truncated to 248 bits) |
| `current_year` | Public | Current year |
| `current_month` | Public | Current month |
| `current_day` | Public | Current day |
| `min_age` | Public | Minimum age to verify |
| `nonce` | Public | Session nonce (prevents proof replay) |

## Output

`binding_hash` (public) — Pedersen hash of `(credential_hash_preimage, nonce)`. Binds the proof to both the credential and the session.

## Usage

```bash
# Install Noir 0.36.0
noirup -v 0.36.0

# Run tests (6 test cases)
nargo test

# Compile to ACIR
nargo compile

# Generate a proof
nargo prove

# Verify the proof
nargo verify
```

## Security notes

- Field inputs are truncated to 248 bits (62 hex chars) to fit the BN254 scalar field without rejection sampling. This provides 2^124 collision resistance — well above the 128-bit target.
- The binding hash prevents proof reuse: a valid proof for session A cannot be replayed in session B.
- The credential binding prevents proof transfer: a proof generated from credential X cannot be claimed as generated from credential Y.

## License

MIT
