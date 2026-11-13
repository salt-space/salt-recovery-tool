#!/usr/bin/env node
/**
 * npm run dev              → GUI (tauri dev)
 * npm run dev fetch …      → headless CLI (no Vite)
 * npm run dev fetch help   → clap --help
 *
 * Note: `npm run dev fetch --help` never reaches this file — npm consumes
 * `--help`/`-h` itself. Use `help` or `npm run dev -- fetch --help`.
 */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let args = process.argv.slice(2);
const CLI = new Set(['fetch', 'decrypt', 'reconstruct', 'robo']);

// `npm run dev fetch --help` never reaches us; `npm run dev fetch help` does.
if (args.length >= 2 && args[args.length - 1] === 'help' && CLI.has(args[0])) {
  args = [...args.slice(0, -1), '--help'];
}

function run(command, commandArgs) {
  const child = spawn(command, commandArgs, {
    cwd: root,
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: process.env,
  });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
  });
}

if (args[0] && CLI.has(args[0])) {
  run('cargo', ['run', '-q', '-p', 'salt-recovery-tool', '--', ...args]);
} else {
  let tauri;
  try {
    tauri = require.resolve('@tauri-apps/cli/tauri.js');
  } catch {
    tauri = 'tauri';
  }
  run(process.execPath, [tauri, 'dev', ...args]);
}
