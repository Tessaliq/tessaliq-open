# receipt-verifier examples

Runnable examples showing how to verify a Tessaliq receipt JWT in three contexts:

| File | Context | Requires |
|---|---|---|
| `cli-example.sh` | Shell / terminal | Built `@tessaliq/receipt-verifier` or bunx/npx alternative |
| `node-example.mjs` | Node.js script | Node ≥ 20, `jose` or the bundled lib |
| `browser-example.html` | Static HTML in a browser | Any modern browser (Chrome ≥ 141, Safari ≥ 26, Firefox ≥ latest) |

All three follow the same contract:

1. Load a receipt JWT from disk / stdin / paste.
2. Fetch the Tessaliq JWKS (`https://api.tessaliq.com/.well-known/jwks.json`) — or use a pre-fetched one for air-gapped runs.
3. Call `jwtVerify` with `algorithms: ['ES256']`, `issuer: 'https://api.tessaliq.com'`, `typ: 'tessaliq-receipt+jwt'`.
4. Print the decoded claims on success, or a structured error on failure.

Spec: [`docs/technique/receipt-spec-v1.md`](../../docs/technique/receipt-spec-v1.md)

## Getting a receipt to test with

If you don't have a real Tessaliq receipt yet, you can still play with the flow:

- The `browser-example.html` includes a "paste JWT" box — any Tessaliq staging receipt you can grab works.
- The `node-example.mjs` includes a short section that generates a sample payload + signs it with a freshly generated key, so you can exercise the verification path without hitting the network.

## Staging vs production

All examples default to `https://api.tessaliq.com` (production). Override via:

- CLI: `tessaliq-receipt-verify receipt.jwt --jwks-url https://api-staging.tessaliq.com/.well-known/jwks.json --issuer https://api-staging.tessaliq.com`
- Node: pass `{ jwksUrl, expectedIssuer }` as the second argument to `verifyReceipt`.
- Browser: edit the `TARGET` constant at the top of the script tag.

## License

MIT — same as the library.
