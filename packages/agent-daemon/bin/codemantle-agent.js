#!/usr/bin/env node

import { spawn } from 'node:child_process'
import { ensureBinary } from '../scripts/lib/downloader.mjs'

const overrideBinaryPath = process.env.CODEMANTLE_AGENT_BINARY_PATH

async function resolveBinaryPath() {
  if (overrideBinaryPath && overrideBinaryPath.trim()) {
    return overrideBinaryPath.trim()
  }
  return ensureBinary({ packageVersion: process.env.npm_package_version })
}

try {
  const binaryPath = await resolveBinaryPath()
  const child = spawn(binaryPath, process.argv.slice(2), {
    stdio: 'inherit',
    env: process.env,
  })

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal)
      return
    }
    process.exit(code ?? 0)
  })

  child.on('error', (error) => {
    process.stderr.write(`[codemantle-agent] Failed to start binary: ${error.message}\n`)
    process.exit(1)
  })
} catch (error) {
  const message = error instanceof Error ? error.message : 'Unknown launch error'
  process.stderr.write(`[codemantle-agent] ${message}\n`)
  process.exit(1)
}
