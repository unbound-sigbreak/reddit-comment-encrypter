#!/usr/bin/env node
// Node >= 22
const http = require('http');
const crypto = require('crypto');
const { URLSearchParams } = require('url');

const CLIENT_ID = process.env.REDDIT_CLIENT_ID || process.argv[2];
const CLIENT_SECRET = process.env.REDDIT_CLIENT_SECRET || process.argv[3];
const REDIRECT_URI = process.env.REDDIT_REDIRECT_URI || 'http://127.0.0.1:8910/callback';
const SCOPES = process.env.REDDIT_SCOPES || 'identity edit history read';
const PORT = 8910;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Usage:');
  console.error('  REDDIT_CLIENT_ID=... REDDIT_CLIENT_SECRET=... node get-refresh-token.js');
  console.error('or ');
  console.error('node --env-file=.env get-refresh-token.js');
  process.exit(1);
}

const state = crypto.randomBytes(16).toString('hex');

const authUrl = new URL('https://www.reddit.com/api/v1/authorize');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('duration', 'permanent'); // REQUIRED to get refresh_token
authUrl.searchParams.set('scope', SCOPES);

console.log('\nOpen this URL in your browser and approve access:\n');
console.log(authUrl.toString(), '\n');

const server = http.createServer(async (req, res) => {
  try {
    if (!req.url.startsWith('/callback')) {
      res.writeHead(404); return res.end('Not found');
    }
    const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
    const code = u.searchParams.get('code');
    const gotState = u.searchParams.get('state');
    if (!code || gotState !== state) {
      res.writeHead(400); return res.end('State mismatch or missing code');
    }

    // Exchange code for tokens
    const TOKEN_URL = 'https://www.reddit.com/api/v1/access_token';
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI
    });

    const r = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'reddit-refresh-helper/1.0'
      },
      body
    });

    const text = await r.text();
    if (!r.ok) {
      res.writeHead(500); res.end('Token exchange failed. Check console.');
      console.error('Exchange error:', r.status, text);
      return;
    }

    const tok = JSON.parse(text);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    if (!tok.refresh_token) {
      res.end('No refresh_token returned. Ensure app is Web type and duration=permanent.');
      console.error('Response missing refresh_token:', tok);
    } else {
      res.end('Refresh token acquired. You can close this tab.');
      console.log('\nREFRESH TOKEN:\n', tok.refresh_token, '\n');
      console.log('Save it securely. Example run of your tool:');
      console.log(`\n  ./index.js --client-id ${CLIENT_ID} --client-secret <SECRET> --refresh-token ${tok.refresh_token} --dry-run ...\n`);
    }
  } catch (e) {
    res.writeHead(500); res.end('Internal error'); console.error(e);
  } finally {
    setTimeout(() => server.close(), 500);
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Listening on http://127.0.0.1:${PORT}/callback ... waiting for Reddit redirect.`);
});
