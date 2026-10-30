import fs from 'node:fs';
import path from 'node:path';
export function readPublicFile(name) {
  return fs.readFileSync(path.join('/fixture/public', name), 'utf8');
}
