import { ensureBinary } from './lib/downloader.mjs'

const skip = process.env.CODEMANTLE_AGENT_SKIP_DOWNLOAD === '1'

if (skip) {
  process.exit(0)
}

try {
  const binaryPath = await ensureBinary({ packageVersion: process.env.npm_package_version })
  process.stdout.write(`[codemantle-agent] Binary ready at ${binaryPath}\n`)
} catch (error) {
  const message = error instanceof Error ? error.message : 'Unknown install error'
  process.stderr.write(`[codemantle-agent] Binary download skipped: ${message}\n`)
}
