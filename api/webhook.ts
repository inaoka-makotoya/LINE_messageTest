// api/webhook.ts
import type { VercelRequest, VercelResponse } from '@vercel/node';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  console.log('INCOMING', req.method, req.url, {
    hasSig: !!req.headers['x-line-signature'],
    ua: req.headers['user-agent'],
  });
  return res.status(200).send('OK'); // ★必ず200を返す
}
