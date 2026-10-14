// Bundles main, preload and renderer with esbuild and copies static assets.
import { build, context } from 'esbuild';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const watch = process.argv.includes('--watch');
const tests = process.argv.includes('--tests');

const { version } = JSON.parse(readFileSync('package.json', 'utf8'));
const common = { bundle: true, sourcemap: true, logLevel: 'info', target: 'es2022', define: { __APP_VERSION__: JSON.stringify(version) } };

if (tests) {
  rmSync('dist-test', { recursive: true, force: true });
  const entryPoints = readdirSync('test').filter((f) => f.endsWith('.test.ts')).map((f) => `test/${f}`);
  await build({ ...common, entryPoints, outdir: 'dist-test', platform: 'node', format: 'cjs', outExtension: { '.js': '.cjs' } });
  process.exit(0);
}

const configs = [
  { ...common, entryPoints: ['src/main/main.ts'], outfile: 'dist/main/main.js', platform: 'node', format: 'cjs', external: ['electron'] },
  { ...common, entryPoints: ['src/main/preload.ts'], outfile: 'dist/main/preload.js', platform: 'node', format: 'cjs', external: ['electron'] },
  { ...common, entryPoints: ['src/renderer/app.ts'], outfile: 'dist/renderer/app.js', platform: 'browser', format: 'iife' },
];

/** Compile the Windows capture helper with the C# compiler that ships with Windows (.NET Framework 4). */
function buildWindowsHelper() {
  if (process.platform !== 'win32') return;
  const csc = join(process.env.WINDIR ?? 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  if (!existsSync(csc)) {
    console.warn('csc.exe not found: skipping the built-in Windows capture helper');
    return;
  }
  mkdirSync('dist/helper', { recursive: true });
  const r = spawnSync(csc, ['-nologo', '-optimize', '-target:winexe', '-out:' + join('dist', 'helper', 'pi-capture.exe'), join('src', 'native', 'win-capture.cs')], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`Building the Windows capture helper failed:
${r.stdout}${r.stderr}`);
  console.log('  dist/helper/pi-capture.exe');
}

function copyStatic() {
  mkdirSync('dist/renderer', { recursive: true });
  cpSync('src/renderer/index.html', 'dist/renderer/index.html');
  cpSync('src/renderer/styles.css', 'dist/renderer/styles.css');
  cpSync('build/icon.png', 'dist/renderer/icon.png');
}

if (watch) {
  for (const c of configs) await (await context(c)).watch();
  copyStatic();
  buildWindowsHelper();
  console.log('watching… (re-run to copy html/css changes)');
} else {
  rmSync('dist', { recursive: true, force: true });
  await Promise.all(configs.map((c) => build(c)));
  copyStatic();
  buildWindowsHelper();
}
