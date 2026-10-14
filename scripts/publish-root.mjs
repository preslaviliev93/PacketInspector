// After `npm run dist:win`, put everything a person needs in the project root:
//   Packet Inspector.exe            open the app (offers to install it if needed)   - app icon
//   Install Packet Inspector.exe    the installer                                     - install icon
//   Uninstall Packet Inspector.exe  remove the installed app                          - uninstall icon
// The two small launchers are compiled with the C# compiler that ships with Windows.
import { copyFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const { version, productName } = JSON.parse(readFileSync('package.json', 'utf8'));
const built = join('release', `${productName} Setup ${version}.exe`);
if (!existsSync(built)) {
  console.error(`Installer not found: ${built} (did electron-builder run?)`);
  process.exit(1);
}
copyFileSync(built, `Install ${productName}.exe`);
console.log(`Install ${productName}.exe  <- ${built}`);

const csc = join(process.env.WINDIR ?? 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
if (process.platform !== 'win32' || !existsSync(csc)) {
  console.warn('C# compiler not found: skipping the launcher programs');
  process.exit(0);
}
const source = join('src', 'native', 'launchers.cs');
const targets = [
  { out: `${productName}.exe`, icon: join('build', 'icon.ico'), defines: [] },
  { out: `Uninstall ${productName}.exe`, icon: join('build', 'uninstall.ico'), defines: ['/define:UNINSTALL'] },
];
for (const t of targets) {
  const r = spawnSync(csc, ['-nologo', '-optimize', '-target:winexe', `-win32icon:${t.icon}`, '-r:System.Windows.Forms.dll', ...t.defines, `-out:${t.out}`, source], { encoding: 'utf8' });
  if (r.status !== 0) {
    console.error(`Building ${t.out} failed:\n${r.stdout}${r.stderr}`);
    process.exit(1);
  }
  console.log(`${t.out}  <- ${source}`);
}

// The older script-based uninstaller is replaced by the .exe above.
rmSync(`Uninstall ${productName}.cmd`, { force: true });
