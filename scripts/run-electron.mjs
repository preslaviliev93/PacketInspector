// Launch Electron with a clean environment. Some hosts (e.g. VS Code tasks)
// export ELECTRON_RUN_AS_NODE=1, which would start Electron as plain Node.
import { spawn } from 'node:child_process';
import electron from 'electron';

const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;
const child = spawn(electron, process.argv.slice(2), { stdio: 'inherit', env });
child.on('close', (code) => process.exit(code ?? 0));
