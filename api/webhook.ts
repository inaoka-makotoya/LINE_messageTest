// api/webhook.ts
import type { VercelRequest, VercelResponse } from '@vercel/node';
import { error } from 'node:console';
import crypto from 'node:crypto';
import test from 'node:test';

async function readRawBody(req: VercelRequest): Promise<string> {
    const chunks: Uint8Array[] = [];
    for await (const c of req as any) chunks.push(c);
    return Buffer.concat(chunks).toString('utf8');
}

function verifyLineSignature(raw: string, sig: string, secret: string): boolean{
    const mac = crypto.createHmac('sha256', secret).update(raw).digest('base64');
    try {
        const aim = Buffer.from(mac);
        const ber = Buffer.from(sig);
        return aim.length === ber.length && crypto.timingSafeEqual(aim, ber);
    } catch {
        return mac === sig; // 古いNodeでも一応安全に対応するため
    }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    // 接続確認・疎通✅は必ず200
    if (req.method === 'GET' || req.method === 'HEAD')return res.status(200).send('OK');
    if (req.method === 'POST' && !req.headers['x-line-signature']) {
        console.log('INCOMING ping-like POST without signature');
        return res.status(200).send('OK(no-sign)');
    }

    try {
        if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method Not Allowed' });

        const secret = process.env.LINE_CHANNEL_SECRET;
        const token = process.env.LINE_CHANNEL_ACCESS_TOKEN;
        if (!secret || !token) {
            console.error('ENV MISSING', { hasSecret: !!secret, hasToken: !!token });
            return res.status(500).json({ ok:false, error: 'Sever env missing' });
        }

        const raw = await readRawBody(req);
        const sig = req.headers['x-line-signature'] as string | undefined;
        if (!sig || !verifyLineSignature(raw, sig, secret)) {
            console.error('BAD SIGNATURE', { hasSig: !!sig });
            return res.status(401).json({ ok:false, error: 'Invalid signature' });
        }

        const { events = [] } = JSON.parse(raw) as { events?: any[] };

        await Promise.all(events.map(async (event: any) => {
            // ログを残すコード
            // console.log('EVENT', event.type, event.source);

            if (event.type === 'follow') {
                const resp = await fetch('https://api.line.me/v2/bot/message/reply',{
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                    body: JSON.stringify({
                        replyToken: event.replyToken,
                        messages: [
                            { type: 'text', text: '友達追加ありがとうございます。' },
                            { type: 'text', text: 'ご不明な点があればこのままメッセージしてください。'},
                        ],
                    }),
                });
                if (!resp.ok) console.error('LINE REPLY ERROR', resp.status, await resp.text());
            }
        }));
        return res.status(200).json({ ok:true });
        } catch (e: any) {
            console.error('UNCAUGHT ERROR', e?.message ?? e, e?.stack);
            return res.status(500).json({ ok: false, error: 'Server error' });
        }
}
