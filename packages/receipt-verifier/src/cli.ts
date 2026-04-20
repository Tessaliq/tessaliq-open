#!/usr/bin/env node
// Minimal CLI to verify a Tessaliq receipt JWT.
// Usage:
//   tessaliq-receipt-verify <path-to-jwt-file>
//   echo "<jwt>" | tessaliq-receipt-verify --stdin
//   tessaliq-receipt-verify <path> --jwks-url https://api-staging.tessaliq.com/.well-known/jwks.json
//
// Exit codes:
//   0 — receipt is valid
//   1 — receipt is invalid (tampered, wrong issuer, wrong algorithm, bad structure)
//   2 — CLI usage error (missing argument, file not found, …)

import { readFileSync } from 'node:fs'
import { verifyReceipt } from './index.js'

function printHelp(): void {
  process.stdout.write(
    'Usage:\n' +
      '  tessaliq-receipt-verify <jwt-file> [options]\n' +
      '  tessaliq-receipt-verify --stdin [options]\n' +
      '\n' +
      'Options:\n' +
      '  --jwks-url <url>     Override JWKS endpoint (default https://api.tessaliq.com/.well-known/jwks.json)\n' +
      '  --issuer <url>       Override expected issuer (default https://api.tessaliq.com)\n' +
      '  --stdin              Read JWT from standard input\n' +
      '  -h, --help           Show this help\n',
  )
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
  }
  return Buffer.concat(chunks).toString('utf-8').trim()
}

interface CliArgs {
  jwtFile?: string
  stdin?: boolean
  jwksUrl?: string
  expectedIssuer?: string
  help?: boolean
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    switch (a) {
      case '-h':
      case '--help':
        args.help = true
        break
      case '--stdin':
        args.stdin = true
        break
      case '--jwks-url':
        args.jwksUrl = argv[++i]
        break
      case '--issuer':
        args.expectedIssuer = argv[++i]
        break
      default:
        if (a && !a.startsWith('-') && !args.jwtFile) args.jwtFile = a
    }
  }
  return args
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))
  if (args.help || (!args.jwtFile && !args.stdin)) {
    printHelp()
    process.exit(args.help ? 0 : 2)
  }

  let jwt: string
  if (args.stdin) {
    jwt = await readStdin()
  } else {
    try {
      jwt = readFileSync(args.jwtFile as string, 'utf-8').trim()
    } catch (err) {
      process.stderr.write(
        `error: cannot read file ${args.jwtFile}: ${err instanceof Error ? err.message : String(err)}\n`,
      )
      process.exit(2)
    }
  }

  if (!jwt) {
    process.stderr.write('error: empty input\n')
    process.exit(2)
  }

  const result = await verifyReceipt(jwt, {
    jwksUrl: args.jwksUrl,
    expectedIssuer: args.expectedIssuer,
  })

  if (result.valid) {
    process.stdout.write('✓ Receipt is valid\n')
    process.stdout.write(JSON.stringify(result.claims, null, 2) + '\n')
    process.exit(0)
  } else {
    process.stderr.write(`✗ Receipt is invalid [${result.error}]: ${result.message}\n`)
    process.exit(1)
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `unexpected error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  )
  process.exit(2)
})
