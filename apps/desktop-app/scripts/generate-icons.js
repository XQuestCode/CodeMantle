// Script to process logo into various icon formats and sizes
import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SOURCE_LOGO = path.join(__dirname, '../../../CodeMantle.png');
const ICONS_DIR = path.join(__dirname, '../src-tauri/icons');
const PUBLIC_ASSETS = path.join(__dirname, '../public/assets');

// Icon sizes needed by Tauri
const ICON_SIZES = [32, 128, 256, 512];

async function generateIcons() {
  console.log('🎨 Generating icons from logo...');
  
  try {
    // Check if source exists
    if (!fs.existsSync(SOURCE_LOGO)) {
      console.error('❌ Source logo not found at:', SOURCE_LOGO);
      process.exit(1);
    }

    // Ensure directories exist
    if (!fs.existsSync(ICONS_DIR)) {
      fs.mkdirSync(ICONS_DIR, { recursive: true });
    }
    if (!fs.existsSync(PUBLIC_ASSETS)) {
      fs.mkdirSync(PUBLIC_ASSETS, { recursive: true });
    }

    // Generate PNG icons in different sizes
    for (const size of ICON_SIZES) {
      const outputPath = path.join(ICONS_DIR, `${size}x${size}.png`);
      await sharp(SOURCE_LOGO)
        .resize(size, size, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
        .png()
        .toFile(outputPath);
      console.log(`  ✓ Generated ${size}x${size}.png`);
    }

    // Generate 128x128@2x.png (256x256 for high DPI)
    await sharp(SOURCE_LOGO)
      .resize(256, 256, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(path.join(ICONS_DIR, '128x128@2x.png'));
    console.log('  ✓ Generated 128x128@2x.png');

    // Generate main icon.png for tray
    await sharp(SOURCE_LOGO)
      .resize(64, 64, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(path.join(ICONS_DIR, 'icon.png'));
    console.log('  ✓ Generated icon.png');

    // Generate Windows ICO file (proper multi-size ICO format)
    const icoSizes = [16, 24, 32, 48, 64, 128, 256];
    const icoPngs = [];
    for (const size of icoSizes) {
      const buf = await sharp(SOURCE_LOGO)
        .resize(size, size, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
        .png()
        .toBuffer();
      icoPngs.push({ size, buf });
    }
    // Build ICO file: header (6 bytes) + directory entries (16 bytes each) + PNG data
    const numImages = icoPngs.length;
    const headerSize = 6 + numImages * 16;
    let dataOffset = headerSize;
    const header = Buffer.alloc(6);
    header.writeUInt16LE(0, 0);      // reserved
    header.writeUInt16LE(1, 2);      // type: 1 = ICO
    header.writeUInt16LE(numImages, 4);
    const dirEntries = [];
    for (const img of icoPngs) {
      const entry = Buffer.alloc(16);
      entry.writeUInt8(img.size >= 256 ? 0 : img.size, 0);  // width (0 = 256)
      entry.writeUInt8(img.size >= 256 ? 0 : img.size, 1);  // height (0 = 256)
      entry.writeUInt8(0, 2);    // color palette
      entry.writeUInt8(0, 3);    // reserved
      entry.writeUInt16LE(1, 4); // color planes
      entry.writeUInt16LE(32, 6); // bits per pixel
      entry.writeUInt32LE(img.buf.length, 8);  // image size
      entry.writeUInt32LE(dataOffset, 12);     // offset
      dirEntries.push(entry);
      dataOffset += img.buf.length;
    }
    const icoBuffer = Buffer.concat([header, ...dirEntries, ...icoPngs.map(i => i.buf)]);
    fs.writeFileSync(path.join(ICONS_DIR, 'icon.ico'), icoBuffer);
    console.log('  ✓ Generated icon.ico (proper ICO format)');

    // Generate macOS ICNS (placeholder - would need special library for real ICNS)
    await sharp(SOURCE_LOGO)
      .resize(512, 512)
      .png()
      .toFile(path.join(ICONS_DIR, 'icon.icns'));
    console.log('  ✓ Generated icon.icns');

    // Copy logo to public assets for frontend
    fs.copyFileSync(SOURCE_LOGO, path.join(PUBLIC_ASSETS, 'logo.png'));
    console.log('  ✓ Copied logo.png to public/assets');
    
    // Generate smaller versions for UI
    await sharp(SOURCE_LOGO)
      .resize(64, 64, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(path.join(PUBLIC_ASSETS, 'logo-64.png'));
    console.log('  ✓ Generated logo-64.png');
    
    await sharp(SOURCE_LOGO)
      .resize(128, 128, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(path.join(PUBLIC_ASSETS, 'logo-128.png'));
    console.log('  ✓ Generated logo-128.png');

    // Generate SVG placeholder for web
    const svgContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
      <text x="50" y="55" text-anchor="middle" font-size="60" fill="#3b82f6">CM</text>
    </svg>`;
    fs.writeFileSync(path.join(PUBLIC_ASSETS, 'logo.svg'), svgContent);
    console.log('  ✓ Generated logo.svg');

    // Copy to control-plane
    const controlPlaneAssets = path.join(__dirname, '../../../apps/control-plane/public');
    if (fs.existsSync(controlPlaneAssets)) {
      fs.copyFileSync(SOURCE_LOGO, path.join(controlPlaneAssets, 'logo.png'));
      fs.copyFileSync(path.join(PUBLIC_ASSETS, 'logo-64.png'), path.join(controlPlaneAssets, 'logo-64.png'));
      fs.copyFileSync(path.join(PUBLIC_ASSETS, 'logo-128.png'), path.join(controlPlaneAssets, 'logo-128.png'));
      console.log('  ✓ Copied logos to control-plane');
    }

    // Copy to agent-daemon
    const agentDaemonAssets = path.join(__dirname, '../../../packages/agent-daemon/assets');
    if (!fs.existsSync(agentDaemonAssets)) {
      fs.mkdirSync(agentDaemonAssets, { recursive: true });
    }
    fs.copyFileSync(SOURCE_LOGO, path.join(agentDaemonAssets, 'logo.png'));
    fs.copyFileSync(path.join(PUBLIC_ASSETS, 'logo-64.png'), path.join(agentDaemonAssets, 'logo-64.png'));
    console.log('  ✓ Copied logos to agent-daemon');

    // Copy to root packages
    const packagesDir = path.join(__dirname, '../../../packages');
    if (fs.existsSync(packagesDir)) {
      const packages = fs.readdirSync(packagesDir, { withFileTypes: true })
        .filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name);
      
      for (const pkg of packages) {
        const pkgAssets = path.join(packagesDir, pkg, 'assets');
        if (!fs.existsSync(pkgAssets)) {
          fs.mkdirSync(pkgAssets, { recursive: true });
        }
        fs.copyFileSync(SOURCE_LOGO, path.join(pkgAssets, 'logo.png'));
      }
      console.log(`  ✓ Copied logos to ${packages.length} packages`);
    }

    console.log('\n✅ All icons generated and distributed successfully!');
    console.log('\n📦 Icon locations:');
    console.log('   • Desktop App (Tauri):', ICONS_DIR);
    console.log('   • Desktop App (UI):', PUBLIC_ASSETS);
    console.log('   • Control Plane: /apps/control-plane/public/');
    console.log('   • Agent Daemon: /packages/agent-daemon/assets/');
    console.log('   • All Packages: /packages/*/assets/');
  } catch (error) {
    console.error('❌ Error generating icons:', error);
    process.exit(1);
  }
}

generateIcons();
