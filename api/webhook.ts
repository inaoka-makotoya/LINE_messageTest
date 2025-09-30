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
        const a = Buffer.from(mac);
        const b = Buffer.from(sig);
        return a.length === b.length && crypto.timingSafeEqual(a, b);
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
        if (req.method !== 'POST') { 
            return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
        }

        const secret = process.env.LINE_CHANNEL_SECRET;
        const token = process.env.LINE_CHANNEL_ACCESS_TOKEN;
        if (!secret || !token) {
            console.error('ENV MISSING', { hasSecret: !!secret, hasToken: !!token });
            return res.status(500).json({ ok:false, error: 'Server env missing' });
        }

        const raw = await readRawBody(req);
        const sig = req.headers['x-line-signature'] as string | undefined;
        if (!sig || !verifyLineSignature(raw, sig, secret)) {
            console.error('BAD SIGNATURE', { hasSig: !!sig, rawLen: raw.length  });
            return res.status(401).json({ ok:false, error: 'Invalid signature' });
        }

        //const { events = [] } = JSON.parse(raw) as { events?: any[] };
        // JSON.parse を安全に（空文字や不正Jsonでも200を返して終わる）
        let payload: { events?: any[] } | null = null;
        try {
            payload = raw ? JSON.parse(raw) : { events: [] };
        } catch (e) {
            console.warn('JSON PARSE WARNING: treating as empty events', String(e), raw.slice(0, 200));
            payload = { events: [] };
        }

        const events = Array.isArray(payload?.events) ? payload!.events : [];

        await Promise.all(events.map(async (event: any) => {
            if (event.type === 'follow') {
                // 友達追加時のメッセージ
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
                return; // このイベントはここで終了させる（Repl）
            }

            // ここからテキストメッセージへの応答
            if (event.type === 'message' && event.message?.type === 'text') {
                const text = (event.message.text || '').trim();

                // 簡易的にコマンド分岐
                let messages: any[] = [];
                if(/^help$/i.test(text)) {
                    messages = [{ type: 'text', text: '使えるコマンド:\nhelp, menu, time, about' }];
                } else if (/^menu$/i.test(text)) {
                    messages = [{ type: 'text', text: '1) お知らせ\n2) お問い合わせ\n3) アクセス' }];
                } else if (/^time$/i.test(text)) {
                    messages = [{ type: 'text', text: `現在時刻： ${new Date().toLocaleString('ja-JP')}` }];
                } else if (/^about$/i.test(text)) {
                    messages = [{ type: 'text', text: 'このボットはテスト版です。' }];
                } else {
                    messages = [{ type: 'text', text: `「${text}」ですね！` }];
                }

                const resp = await fetch('https://api.line.me/v2/bot/message/reply',{
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                    body: JSON.stringify({ replyToken: event.replyToken, messages }),
                });
                if (!resp.ok) console.error('LINE REPLY ERROR', resp.status, await resp.text());
                return;
            }
            // この下に他のイベントを追加するコードを書く
            
        }));
        return res.status(200).json({ ok:true });
        } catch (e: any) {
            console.error('UNCAUGHT ERROR', e?.message ?? e, e?.stack);
            return res.status(200).json({ ok: false, error: 'Server error(masked)' });
        }
}
