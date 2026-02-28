import { createHash } from 'node:crypto'
import { createWriteStream } from 'node:fs'
import { chmod, mkdir, readFile, rename, stat, unlink } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'

const RELEASE_HOST = 'https://github.com/XQuestCode/codemantle/releases/download'

function parseVersion(version) {
  if (!version || typeof version !== 'string') {
    throw new Error('Missing package version for binary resolution')
  }
  return version.startsWith('v') ? version : `v${version}`
}

export function resolveTarget() {
  const platform = process.platform
  const arch = process.arch

  if (platform === 'win32' && arch === 'x64') {
    return { platform, arch, artifact: 'codemantle-agent-windows-x64.exe' }
  }
  if (platform === 'darwin' && arch === 'x64') {
    return { platform, arch, artifact: 'codemantle-agent-darwin-x64' }
  }
  if (platform === 'darwin' && arch === 'arm64') {
    return { platform, arch, artifact: 'codemantle-agent-darwin-arm64' }
  }
  if (platform === 'linux' && arch === 'x64') {
    return { platform, arch, artifact: 'codemantle-agent-linux-x64' }
  }
  if (platform === 'linux' && arch === 'arm64') {
    return { platform, arch, artifact: 'codemantle-agent-linux-arm64' }
  }

  throw new Error(`Unsupported platform for CodeMantle Agent binary: ${platform}/${arch}`)
}

function resolveBaseUrl(versionTag) {
  const override = process.env.CODEMANTLE_AGENT_BINARY_BASE_URL
  if (override && override.trim()) {
    return override.replace(/\/$/, '')
  }
  return `${RELEASE_HOST}/${versionTag}`
}

function resolveInstallDirectory(version) {
  const override = process.env.CODEMANTLE_AGENT_INSTALL_DIR
  if (override && override.trim()) {
    return path.resolve(override)
  }
  return path.join(os.homedir(), '.codemantle', 'agent-daemon', version)
}

async function sha256File(filePath) {
  const buffer = await readFile(filePath)
  return createHash('sha256').update(buffer).digest('hex')
}

async function fetchToFile(url, destination) {
  const response = await fetch(url)
  if (!response.ok || !response.body) {
    throw new Error(`Download failed (${response.status}) for ${url}`)
  }
  const tempPath = `${destination}.tmp`
  await pipeline(response.body, createWriteStream(tempPath))
  await rename(tempPath, destination)
}

async function parseChecksums(checksumPath) {
  const content = await readFile(checksumPath, 'utf8')
  const checksums = new Map()
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line) {
      continue
    }
    const parts = line.split(/\s+/)
    if (parts.length < 2) {
      continue
    }
    const [hash, filename] = parts
    checksums.set(filename.replace(/^\*/, ''), hash.toLowerCase())
  }
  return checksums
}

export async function ensureBinary(options = {}) {
  const packageVersion = options.packageVersion ?? process.env.npm_package_version
  const versionTag = parseVersion(packageVersion)
  const target = resolveTarget()
  const installDir = resolveInstallDirectory(versionTag)
  const binaryPath = path.join(installDir, target.artifact)

  try {
    const existing = await stat(binaryPath)
    if (existing.isFile()) {
      return binaryPath
    }
  } catch {
  }

  await mkdir(installDir, { recursive: true })
  const baseUrl = resolveBaseUrl(versionTag)
  const checksumPath = path.join(installDir, 'checksums.txt')
  await fetchToFile(`${baseUrl}/checksums.txt`, checksumPath)

  const checksums = await parseChecksums(checksumPath)
  const expectedHash = checksums.get(target.artifact)
  if (!expectedHash) {
    throw new Error(`Missing checksum entry for ${target.artifact}`)
  }

  await fetchToFile(`${baseUrl}/${target.artifact}`, binaryPath)
  const actualHash = await sha256File(binaryPath)
  if (actualHash !== expectedHash) {
    await unlink(binaryPath).catch(() => {})
    throw new Error(`Checksum mismatch for ${target.artifact}`)
  }

  if (process.platform !== 'win32') {
    await chmod(binaryPath, 0o755)
  }

  return binaryPath
}
