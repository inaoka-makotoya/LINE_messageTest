// api/webhook.ts

import type { VercelRequest, VercelResponse } from '@vercel/node';
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
    if (req.method === 'GET' || req.method === 'HEAD') return res.status(200).send('OK');  // 接続確認
    if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method Not Allowed'});

    const secret = process.env.LINE_CHANNEL_SECRET!;
    const token  = process.env.LINE_CHANNEL_ACCESS_TOKEN!;
    const raw    = await readRawBody(req);
    const sig    = req.headers['x-line-signature'] as string | undefined;

    if (!sig || !verifyLineSignature(raw, sig, secret)){
        return res.status(401).json({ ok: false, error: 'Invalid signature' });
    }

    const { events = [] } = JSON.parse(raw) as { events?: any[] };
    await Promise.all(events.map(async (event: any) => {
        if (event.type === 'follow') {
            const resp = await fetch('https://api.line.me/v2/bot/message/reply', {
                method: 'POST',
                headers: { 'Content=Type': 'application/json', Authorization: `Bearer ${token}`},
                body: JSON.stringify({
                    replyToken: event.replyToken,
                    messages:[
                        { type: 'text', text: '友達追加ありがとうございます!'},
                        { type: 'text', text: 'ご不明な点がございましたらこのままメッセージをしてください。'}
                    ]
                })
            });
            if (!resp.ok) console.error('LINE reply error', resp.status, await resp.text());
        }
    }));

    return res.status(200).json( { ok: true });

    
}