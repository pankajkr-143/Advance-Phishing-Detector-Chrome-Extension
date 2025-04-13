import { copyFileSync, mkdirSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(__dirname, '..');

// Ensure icons directory exists
mkdirSync(resolve(projectRoot, 'dist/icons'), { recursive: true });

// Copy manifest.json to dist
copyFileSync(
  resolve(projectRoot, 'manifest.json'),
  resolve(projectRoot, 'dist/manifest.json')
);

// Copy icons
const iconSizes = [16, 48, 128];
iconSizes.forEach(size => {
  copyFileSync(
    resolve(projectRoot, `public/icons/icon${size}.png`),
    resolve(projectRoot, `dist/icons/icon${size}.png`)
  );
});