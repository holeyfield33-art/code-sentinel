import fs from 'node:fs';
import path from 'node:path';
export function readPublicFile(name) {
  const base = fs.realpathSync('/fixture/public');
  const resolved = fs.realpathSync(path.resolve(base, name));
  if (!resolved.startsWith(base + path.sep)) throw new Error('forbidden');
  return fs.readFileSync(resolved, 'utf8');
}
