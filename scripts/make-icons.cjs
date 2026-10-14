// Renders build/icon.svg into the PNG and ICO files the app, installer,
// uninstaller and launchers use. Uses Electron's own renderer, so no image
// tools need to be installed.
//   npm run icons
//
// Variants share the app artwork so they read as one family:
//   icon.ico       the app itself
//   install.ico    app + green download badge
//   uninstall.ico  app + red remove badge
const { app, BrowserWindow, nativeImage } = require('electron');
const { readFileSync, writeFileSync, mkdirSync } = require('node:fs');
const { join } = require('node:path');

const root = join(__dirname, '..');
const SIZE = 1024;
const ICO_SIZES = [16, 24, 32, 48, 64, 128, 256];

const BADGES = {
  install:
    '<circle cx="404" cy="404" r="100" fill="#0ca30c" stroke="#ffffff" stroke-width="18"/>' +
    '<path d="M404 346 V452 M358 410 L404 456 L450 410" fill="none" stroke="#ffffff" stroke-width="30" stroke-linecap="round" stroke-linejoin="round"/>',
  uninstall:
    '<circle cx="404" cy="404" r="100" fill="#d03b3b" stroke="#ffffff" stroke-width="18"/>' +
    '<path d="M352 404 H456" fill="none" stroke="#ffffff" stroke-width="32" stroke-linecap="round"/>',
};

/** ICO container holding PNG-compressed images (supported since Windows Vista). */
function toIco(pngs) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(pngs.length, 4);
  const entries = [];
  let offset = 6 + 16 * pngs.length;
  for (const { size, data } of pngs) {
    const e = Buffer.alloc(16);
    e[0] = size >= 256 ? 0 : size;
    e[1] = size >= 256 ? 0 : size;
    e.writeUInt16LE(1, 4);
    e.writeUInt16LE(32, 6);
    e.writeUInt32LE(data.length, 8);
    e.writeUInt32LE(offset, 12);
    offset += data.length;
    entries.push(e);
  }
  return Buffer.concat([header, ...entries, ...pngs.map((p) => p.data)]);
}

async function render(svg) {
  const sized = svg.replace(/width="512" height="512"/, `width="${SIZE}" height="${SIZE}"`);
  const html = `<html><body style="margin:0;background:transparent;overflow:hidden">${sized}</body></html>`;
  const win = new BrowserWindow({ width: SIZE, height: SIZE, show: false, frame: false, transparent: true, webPreferences: { offscreen: true } });
  // Keep the latest painted frame; take it once the page has loaded and settled.
  let last = null;
  win.webContents.on('paint', (_e, _dirty, img) => { last = img; });
  await win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
  await new Promise((r) => setTimeout(r, 800));
  win.webContents.invalidate();
  await new Promise((r) => setTimeout(r, 400));
  win.destroy();
  if (!last || last.isEmpty()) throw new Error('Icon did not render');
  return nativeImage.createFromBuffer(last.toPNG()).crop({ x: 0, y: 0, width: SIZE, height: SIZE });
}

app.disableHardwareAcceleration();
// Each variant renders in its own hidden window; closing one must not end the app.
app.on('window-all-closed', () => {});
app.whenReady().then(async () => {
  const base = readFileSync(join(root, 'build', 'icon.svg'), 'utf8');
  mkdirSync(join(root, 'build', 'icons'), { recursive: true });

  const full = await render(base);
  const at = (img, n) => img.resize({ width: n, height: n, quality: 'best' }).toPNG();
  writeFileSync(join(root, 'build', 'icon.png'), at(full, 512));
  for (const n of [16, 32, 48, 64, 128, 256, 512]) writeFileSync(join(root, 'build', 'icons', `${n}x${n}.png`), at(full, n));
  writeFileSync(join(root, 'build', 'icon.ico'), toIco(ICO_SIZES.map((size) => ({ size, data: at(full, size) }))));

  for (const [name, badge] of Object.entries(BADGES)) {
    const img = await render(base.replace('</svg>', `${badge}</svg>`));
    writeFileSync(join(root, 'build', `${name}.ico`), toIco(ICO_SIZES.map((size) => ({ size, data: at(img, size) }))));
    writeFileSync(join(root, 'build', `${name}.png`), at(img, 256));
  }
  console.log('Wrote build/icon.png, build/icon.ico, build/icons/*.png, build/install.ico, build/uninstall.ico');
  app.quit();
});
