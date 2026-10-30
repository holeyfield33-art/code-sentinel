import http from 'node:http';
import { readPublicFile } from './files.mjs';
export function onRequest(req, res) {
  const name = new URL(req.url, 'http://localhost').searchParams.get('file');
  try {
    res.end(readPublicFile(name));
  } catch {
    res.writeHead(403); res.end('forbidden');
  }
}
http.createServer(onRequest).listen(3210, '127.0.0.1');
