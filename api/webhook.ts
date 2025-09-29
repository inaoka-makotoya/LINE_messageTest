// api/webhook.ts

import type { VercelRequest, VercelResponse } from '@vercel/node';
import { error } from 'node:console';
//import { error } from 'node:console';
import crypto from 'node:crypto';
//import { text } from 'node:stream/consumers';

async function readRawBody(req: VercelRequest): Promise<string> {
    const chunks: Uint8Array[] = [];
    for await (const c of req as any) chunks.push(c);
    return Buffer.concat(chunks).toString('utf8');
}

function verifyLineSignature(raw: string, sig: string, secret: string): boolean {
    const hmac = crypto.createHmac('sha256', secret).update(raw).digest('base64');
    try{
        const aim = Buffer.from(hmac);
        const bdash = Buffer.from(sig);
        if( aim.length !== bdash.length) return false;
        return crypto.timingSafeEqual(aim, bdash);
    } catch {
        return hmac === sig;
    }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try{
    if (req.method === 'GET' || req.method === 'HEAD') return res.status(200).send('OK');  // 接続確認
    if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method Not Allowed'});

    const secret = process.env.LINE_CHANNEL_SECRET!;
    const token  = process.env.LINE_CHANNEL_ACCESS_TOKEN!;
    if (!secret || !token) {
        console.error('ENV MISSING', { hasSecret: !!secret, hasToken: !!token });
        return res.status(500).json({ ok: false, error: 'Server env missing' }); 
    }
   
    const raw = await readRawBody(req);
    const sig = req.headers['x-line-signature'] as string | undefined;

    if (!sig || !verifyLineSignature(raw, sig, secret)){
        return res.status(401).json({ ok: false, error: 'Invalid signature' });
    }

    let payload: { events?: any[] };
    try{
        payload = JSON.parse(raw);
    } catch (e) {
        console.error('JSON PARSE ERROR', e, raw.slice(0, 200));
        return res.status(400).json( { ok: false, error: 'Bad JSON' });
    }

    const events = payload.events ?? [];
    await Promise.all(events.map(async (event) => {
        // 必要ならここでロギング
        // console.log('Event', event.type, event.sourece);
 if (event.type === 'follow') {
        const reply = {
          replyToken: event.replyToken,
          messages: [
            { type: 'text', text: '友だち追加ありがとうございます！' },
            { type: 'text', text: 'ご不明点があればこのままメッセージしてください。' }
          ]
        };

        const resp = await fetch('https://api.line.me/v2/bot/message/reply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(reply)
        });

        if (!resp.ok) {
          const txt = await resp.text();
          console.error('LINE REPLY ERROR', resp.status, txt);
          // 返信失敗でも webhook 自体は200で返す（LINEのリトライ嵐を防ぐ）
        }
      }
      // 他のイベントは無視してOK
    }));

    return res.status(200).json({ ok: true });
  } catch (e: any) {
    console.error('UNCAUGHT ERROR', e?.message ?? e, e?.stack);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
}