import { chmod, readFile, writeFile } from 'node:fs/promises'

const source = await readFile(new URL('../dist/index.js', import.meta.url), 'utf8')
const cliBody = `#!/usr/bin/env node\n${source}`
await writeFile(new URL('../dist/cli.js', import.meta.url), cliBody, 'utf8')
await chmod(new URL('../dist/cli.js', import.meta.url), 0o755).catch(() => {})
