#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { setTimeout: sleep } = require('timers/promises');

const args = process.argv.slice(2);
const opts = {
  // Auth
  clientId: process.env.REDDIT_CLIENT_ID || null,
  clientSecret: process.env.REDDIT_CLIENT_SECRET || null,
  refreshToken: process.env.REDDIT_REFRESH_TOKEN || null,

  // Optional config file
  configPath: process.env.REDDIT_CRYPT_CONFIG || path.join(os.homedir(), '.reddit-crypt.json'),

  // Modes / Keys (used in planning phase)
  mode: 'aes',                 // 'aes' | 'hybrid'
  embedPsk: false,             // AES: append "<delimiter><base64>" after ciphertext
  pskDelim: 'AES-PSK:',        // configurable delimiter used for embed & detection
  pskFrom: null,               // base64 of 32 bytes; if set, NEVER auto-generate AES keys
  keyDir: path.join(os.homedir(), '.keys'),
  keyId: null,
  pubKeyPath: null,
  privKeyPath: null,

  // Filters (planning)
  start: null, end: null,
  onlySubs: null, skipSubs: null,
  minScore: null, maxScore: null,
  contains: null, notContains: null,

  // Behaviour (planning)
  onlyPlain: false,            // never rotate if already encrypted
  limit: null,                 // cap comments fetched (scanned)
  maxEdits: null,              // cap planned edits (for plan size)
  resumeFile: null,            // persist 'after' cursor
  restore: false,              // decrypt -> plaintext (from ciphertext in-place)
  backupPath: null,            // backups are used on execute
  restoreFrom: null,           // restore verbatim from backup file (planning decides "to")

  // Plan / execute
  planPath: null,              // write JSON plan of edits
  executePath: null,           // execute from JSON plan

  // Word-salad prefix (planning)
  wordListPath: null,          // JSON file; either an array or {words:[...]}
  prefix: null,                // literal prefix to place before token
  prefixLen: null,             // "80,240" target char window (uses word list)
  prefixSentences: null,       // "3,6" sentence count range (uses word list)
  prefixCommaP: 0.25,          // probability that a random comma appears in a sentence
  postfix: null,               // literal postfix to place after token/psk

  // Networking
  concurrency: 1,
  jitterMs: [800, 2000],
  backoffBaseMs: 1500,

  // Retry (JSON-level ratelimit, used in execute)
  maxEditRetries: 5,

  // Output & safety
  consoleLog: false,           // print human-readable log to console at end
  verifyAfter: false,
  verbose: false,

  // Webhook (summary on completion)
  webhook: null                // URL for POST summary, e.g. https://example.com/hook
};

const pickNext = (arr, index) => (index + 1 < arr.length ? arr[index + 1] : null);

const printHelpAndExit = (code) => {
  console.log(`
Reddit Comment Encryptor/Rotator/Restorer (OAuth refresh-token)

2-step workflow (all edits go via a JSON plan):

  # 1) PLAN: fetch + compute new bodies, write JSON plan (NO edits)
  ./index.js \\
    --client-id <id> --client-secret <secret> --refresh-token <token> \\
    --mode aes|hybrid [crypto/options...] \\
    [filters/behaviour...] \\
    --plan plan.json [--console] [--verbose]

  # 2) EXECUTE: apply edits from an existing plan.json
  ./index.js \\
    --client-id <id> --client-secret <secret> --refresh-token <token> \\
    --execute plan.json [--concurrency N] [--jitter-ms 800,2000] [--max-edits N] \\
    [--backup backup.json] [--verify-after] [--console] [--verbose]

Single-run plan+execute is allowed and still uses the plan file:

  ./index.js ... --plan plan.json --execute plan.json

If you omit BOTH --plan and --execute, it defaults to:
  --plan ./reddit-crypt-plan.json   (no edits this run)

AES mode:
  * Emits A|<base64( 12-byte IV || ciphertext || tag )>.
  * Your Web AES tool can decrypt the base64 tail if you manually strip "A|".
  * Optional PSK line is appended as: "\\n<delimiter><base64-key>".

Use --console to print the human-readable log to stdout.
--verbose prints step-by-step details while running.

Webhook:
  --webhook <url>   POST a JSON summary on completion (plan/execute).`);
  process.exit(code);
};

const parseArgs = () => {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case '--client-id': opts.clientId = pickNext(args, i++); break;
      case '--client-secret': opts.clientSecret = pickNext(args, i++); break;
      case '--refresh-token': opts.refreshToken = pickNext(args, i++); break;
      case '--config': opts.configPath = pickNext(args, i++); break;

      case '--mode': opts.mode = pickNext(args, i++); break;
      case '--embed-psk': opts.embedPsk = true; break;
      case '--psk-delim': opts.pskDelim = pickNext(args, i++); break;
      case '--psk-from': opts.pskFrom = pickNext(args, i++); break;
      case '--key-dir': opts.keyDir = pickNext(args, i++); break;
      case '--key-id': opts.keyId = pickNext(args, i++); break;
      case '--pub': opts.pubKeyPath = pickNext(args, i++); break;
      case '--priv': opts.privKeyPath = pickNext(args, i++); break;

      case '--start': opts.start = pickNext(args, i++); break;
      case '--end': opts.end = pickNext(args, i++); break;
      case '--only-subreddits': opts.onlySubs = pickNext(args, i++); break;
      case '--skip-subreddits': opts.skipSubs = pickNext(args, i++); break;
      case '--min-score': opts.minScore = Number(pickNext(args, i++)); break;
      case '--max-score': opts.maxScore = Number(pickNext(args, i++)); break;
      case '--contains': opts.contains = pickNext(args, i++); break;
      case '--not-contains': opts.notContains = pickNext(args, i++); break;

      case '--only-plain': opts.onlyPlain = true; break;
      case '--limit': opts.limit = Number(pickNext(args, i++)); break;
      case '--max-edits': opts.maxEdits = Number(pickNext(args, i++)); break;
      case '--resume': opts.resumeFile = pickNext(args, i++); break;
      case '--restore': opts.restore = true; break;
      case '--backup': opts.backupPath = pickNext(args, i++); break;
      case '--restore-from': opts.restoreFrom = pickNext(args, i++); break;

      case '--plan': opts.planPath = pickNext(args, i++); break;
      case '--execute': opts.executePath = pickNext(args, i++); break;

      case '--wordlist': opts.wordListPath = pickNext(args, i++); break;
      case '--prefix': opts.prefix = pickNext(args, i++); break;
      case '--prefix-len': opts.prefixLen = pickNext(args, i++); break;
      case '--prefix-sentences': opts.prefixSentences = pickNext(args, i++); break;
      case '--prefix-comma-p': opts.prefixCommaP = Number(pickNext(args, i++)); break;
      case '--postfix': opts.postfix = pickNext(args, i++); break;

      case '--concurrency': opts.concurrency = Math.max(1, Number(pickNext(args, i++))); break;
      case '--jitter-ms': {
        const jitterText = pickNext(args, i++);
        const [jitterMin, jitterMax] = jitterText.split(',').map(Number);
        if (Number.isFinite(jitterMin) && Number.isFinite(jitterMax) && jitterMin <= jitterMax) {
          opts.jitterMs = [jitterMin, jitterMax];
        }
        break;
      }
      case '--backoff-base-ms': opts.backoffBaseMs = Number(pickNext(args, i++)); break;

      case '--max-edit-retries': opts.maxEditRetries = Math.max(0, Number(pickNext(args, i++))); break;

      case '--console': opts.consoleLog = true; break;
      case '--verify-after': opts.verifyAfter = true; break;
      case '--verbose': opts.verbose = true; break;

      case '--webhook': opts.webhook = pickNext(args, i++); break;

      case '--help':
      case '-h': printHelpAndExit(0); break;
    }
  }
};

const loadConfig = () => {
  try {
    if (opts.configPath && fs.existsSync(opts.configPath)) {
      const configJson = JSON.parse(fs.readFileSync(opts.configPath, 'utf8'));
      for (const [key, value] of Object.entries(configJson)) {
        if (opts[key] == null || opts[key] === false || opts[key] === '') opts[key] = value;
      }
    }
  } catch (error) {
    console.warn('WARN: failed to load config:', error.message);
  }
};

parseArgs();
loadConfig();

if (!opts.planPath && !opts.executePath) {
  opts.planPath = path.resolve(process.cwd(), 'reddit-crypt-plan.json');
  if (opts.verbose) {
    console.log(`No --plan/--execute specified; defaulting to plan file: ${opts.planPath}`);
  }
}

const isPureExecute = !!opts.executePath && !opts.planPath;

if (!opts.clientId || !opts.clientSecret || !opts.refreshToken) {
  console.error('Provide --client-id, --client-secret, and --refresh-token ', {
    clientId: !!opts.clientId,
    clientSecret: !!opts.clientSecret,
    refreshToken: !!opts.refreshToken
  });
  printHelpAndExit(1);
}

if (!isPureExecute) {
  if (!['aes', 'hybrid'].includes(opts.mode)) {
    console.error('Invalid --mode. Use "aes" or "hybrid".');
    process.exit(1);
  }
  if (opts.mode === 'hybrid' && !opts.keyId && !opts.pubKeyPath) {
    console.error('Hybrid mode requires --key-id (under --key-dir) or --pub <pub.pem>.');
    process.exit(1);
  }
  if (opts.mode === 'aes' && opts.pskFrom && !/^[A-Za-z0-9+/=]+$/.test(opts.pskFrom)) {
    console.error('--psk-from must be base64.');
    process.exit(1);
  }
}

const API_BASE = 'https://oauth.reddit.com';
const TOKEN_URL = 'https://www.reddit.com/api/v1/access_token';
const UA = 'reddit-crypt/4.2';
const REDDIT_COMMENT_MAX = 10_000;
const AES_HEADER_CHAR = 'A';
const MAGIC = Buffer.from('RCMT', 'ascii');
const VERSION = 0x01;
const MODE = { HYBRID: 0x02 };

const b64ToBuf = (text) => { try { return Buffer.from(text, 'base64'); } catch { return null; } };
const bufToB64 = (buffer) => buffer.toString('base64');
const rand = (byteCount) => crypto.randomBytes(byteCount);
const be16 = (value) => { const buffer = Buffer.alloc(2); buffer.writeUInt16BE(value); return buffer; };
const be32 = (value) => { const buffer = Buffer.alloc(4); buffer.writeUInt32BE(value); return buffer; };

const withinDate = (createdUtc, start, end) => {
  const timeMs = createdUtc * 1000;
  if (start && timeMs < Date.parse(start)) return false;
  if (end && timeMs > Date.parse(end)) return false;
  return true;
};

const compileRegex = (pattern) => {
  if (!pattern) return null;
  try {
    return new RegExp(pattern, 'i');
  } catch (error) {
    console.warn('WARN: bad regex:', pattern, error.message);
    return null;
  }
};

const oneLine = (text) => String(text ?? '').split('\r').join('').split('\n').join('\\n');

const isB64Char = (ch) => {
  const code = ch.charCodeAt(0);
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || (code >= 48 && code <= 57) || ch === '+' || ch === '/' || ch === '=';
};

const isB64Token = (token) => {
  if (!token || token.length < 32) return false;
  for (let i = 0; i < token.length; i++) if (!isB64Char(token[i])) return false;
  return true;
};

const isWS = (ch) => ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t' || ch === '\f' || ch === '\v';

const findCryptoToken = (body) => {
  const text = String(body || '');
  const length = text.length;
  let index = 0;
  while (index < length) {
    while (index < length && isWS(text[index])) index++;
    if (index >= length) break;
    const start = index;
    while (index < length && !isWS(text[index])) index++;
    const token = text.slice(start, index);
    if (!token) continue;

    const barIdx = token.indexOf('|');
    if (barIdx > 0 && barIdx < token.length - 1) {
      const header = token.slice(0, barIdx);
      const tail = token.slice(barIdx + 1);
      if (header.length === 1 && header === AES_HEADER_CHAR && isB64Token(tail)) {
        const buffer = b64ToBuf(tail);
        if (buffer && buffer.length >= 12 + 16 + 1) {
          return { token, start, end: index, kind: 'aes' };
        }
      }
    }

    if (isB64Token(token)) {
      const buffer = b64ToBuf(token);
      if (!buffer) continue;
      if (buffer.length >= 4 &&
          buffer[0] === 0x52 &&
          buffer[1] === 0x43 &&
          buffer[2] === 0x4d &&
          buffer[3] === 0x54) {
        return { token, start, end: index, kind: 'hybrid' };
      }
    }
  }
  return null;
};

const extractPSKAfter = (body, fromIdx) => {
  const tag = String(opts.pskDelim || 'AES-PSK: ');
  const text = String(body || '');
  const index = text.indexOf(tag, Math.max(0, fromIdx || 0));
  if (index === -1) return null;
  const start = index + tag.length;
  let cursor = start;
  while (cursor < text.length && isB64Char(text[cursor])) cursor++;
  const val = text.slice(start, cursor).trim();
  return val || null;
};

let WORDS = null;
let warnedEmptyWordlist = false;

const loadWordListOnce = () => {
  if (!opts.wordListPath) return;
  try {
    const txt = fs.readFileSync(path.resolve(opts.wordListPath), 'utf8');
    const parsed = JSON.parse(txt);
    const array = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.words) ? parsed.words : null);
    if (!array || array.length === 0) {
      console.warn('WARN: word list file is empty; proceeding without prefix.');
      warnedEmptyWordlist = true;
      WORDS = [];
      return;
    }
    WORDS = array.map((item) => String(item).trim()).filter(Boolean);
  } catch (error) {
    console.warn('WARN: failed to load word list:', error.message, '(proceeding without prefix)');
    warnedEmptyWordlist = true;
    WORDS = [];
  }
};

if (!isPureExecute) loadWordListOnce();

const capFirst = (text) => (text ? (text[0].toUpperCase() + text.slice(1)) : text);

const chooseWord = () => {
  if (!WORDS || WORDS.length === 0) return null;
  return WORDS[Math.floor(Math.random() * WORDS.length)];
};

const makeSentence = () => {
  const wordCount = 6 + Math.floor(Math.random() * 9);
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    const word = chooseWord();
    if (!word) break;
    words.push(word);
  }
  if (words.length === 0) return '';
  const probability = Number.isFinite(opts.prefixCommaP) ? Math.max(0, Math.min(1, opts.prefixCommaP)) : 0.25;
  if (probability > 0 && Math.random() < probability && words.length >= 6) {
    const position = 2 + Math.floor(Math.random() * (words.length - 3));
    words[position] = words[position] + ',';
  }
  return capFirst(words.join(' ')) + '.';
};

const genPrefix = () => {
  const generationRequested = Boolean(opts.prefixSentences || opts.prefixLen);
  if (!generationRequested) return '';

  if ((!WORDS || WORDS.length === 0)) {
    if (!warnedEmptyWordlist) {
      console.warn('WARN: prefix generation requested but word list is empty/missing; proceeding without wordlist prefix.');
      warnedEmptyWordlist = true;
    }
    return '';
  }

  if (opts.prefixSentences) {
    let minSentences = 1;
    let maxSentences = 1;
    try {
      const [x, y] = String(opts.prefixSentences).split(',');
      minSentences = Math.max(1, parseInt(x, 10) || 1);
      maxSentences = Math.max(minSentences, parseInt(y, 10) || minSentences);
    } catch {}
    const count = minSentences + Math.floor(Math.random() * (maxSentences - minSentences + 1));
    const out = [];
    for (let i = 0; i < count; i++) {
      const sentence = makeSentence();
      if (!sentence) break;
      out.push(sentence);
    }
    return out.join(' ');
  }

  if (opts.prefixLen) {
    let min = 0;
    let max = 0;
    try {
      const [x, y] = String(opts.prefixLen).split(',');
      min = Math.max(0, parseInt(x, 10) || 0);
      max = Math.max(min, parseInt(y, 10) || min);
    } catch {}
    const target = Math.max(0, Math.min(2000, Math.floor(min + Math.random() * (max - min + 1))));
    let out = '';
    while (out.length < target) {
      const sentence = makeSentence();
      if (!sentence) break;
      out += (out ? ' ' : '') + sentence;
    }
    return out.slice(0, target).trim();
  }

  return '';
};

const buildPrefixBlock = () => {
  const literal = opts.prefix ? String(opts.prefix) : '';
  const generated = genPrefix();
  if (literal && generated) return literal + '\n\n' + generated;
  if (literal) return literal;
  if (generated) return generated;
  return '';
};

const jitter = (range) => {
  const [min, max] = range;
  return min + Math.floor(Math.random() * (max - min + 1));
};

const aesEncrypt = (plainBuf, keyBuf, nonce) => {
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, nonce);
  const enc = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { enc, tag };
};

const aesDecrypt = (enc, tag, keyBuf, nonce) => {
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, nonce);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec;
};

const buildHybridToken = ({ nonce, ek, enc, tag }) => {
  const head = Buffer.concat([
    MAGIC,
    Buffer.from([VERSION]),
    Buffer.from([MODE.HYBRID]),
    Buffer.from([0]),
    Buffer.from([nonce.length]),
    be16(ek ? ek.length : 0),
    nonce,
    ek || Buffer.alloc(0),
    be32(enc.length),
    enc,
    tag
  ]);
  return bufToB64(head);
};

const parseHybridHeader = (buffer) => {
  try {
    let off = 0;
    if (buffer.length < 4 + 1 + 1 + 1 + 1 + 2 + 4 + 16) return { ok: false, err: 'too-short' };
    if (!buffer.subarray(0, 4).equals(MAGIC)) return { ok: false, err: 'bad-magic' };
    off += 4;
    const version = buffer[off++]; if (version !== VERSION) return { ok: false, err: 'bad-version' };
    const mode = buffer[off++]; if (mode !== MODE.HYBRID) return { ok: false, err: 'bad-mode' };
    const flags = buffer[off++];
    const nonceLen = buffer[off++]; if (nonceLen < 8 || nonceLen > 32) return { ok: false, err: 'bad-nonce-len' };
    const ekLen = buffer.readUInt16BE(off); off += 2;
    const nonce = buffer.subarray(off, off + nonceLen); off += nonceLen;
    const ek = ekLen ? buffer.subarray(off, off + ekLen) : Buffer.alloc(0); off += ekLen;
    const cipherLen = buffer.readUInt32BE(off); off += 4;
    const cipher = buffer.subarray(off, off + cipherLen); off += cipherLen;
    const tag = buffer.subarray(off, off + 16); off += 16;
    if (cipher.length === 0 || tag.length !== 16) return { ok: false, err: 'bad-cipher-tag' };
    return { ok: true, nonce, ek, cipher, tag, flags };
  } catch (error) {
    return { ok: false, err: error.message };
  }
};

const parseHybridTokenB64 = (b64) => {
  const buffer = b64ToBuf(b64);
  if (!buffer) return { ok: false, err: 'base64-decode-failed' };
  return parseHybridHeader(buffer);
};

const loadKeyMaterial = () => {
  let pub = null;
  let priv = null;
  if (!isPureExecute && (opts.mode === 'hybrid' || opts.restore)) {
    let pubPath = opts.pubKeyPath;
    let privPath = opts.privKeyPath;
    if (opts.keyId) {
      const base = path.resolve(opts.keyDir, opts.keyId);
      if (!pubPath) pubPath = base + '.pub.pem';
      if (!privPath) privPath = base + '.priv.pem';
    }
    if (pubPath && fs.existsSync(pubPath)) pub = fs.readFileSync(pubPath, 'utf8');
    if (privPath && fs.existsSync(privPath)) priv = fs.readFileSync(privPath, 'utf8');
  }
  return { pub, priv };
};

const rsaWrapAesKey = (aesKeyBuf, pubPem) => crypto.publicEncrypt(
  { key: pubPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  aesKeyBuf
);

const rsaUnwrapAesKey = (encKeyBuf, privPem) => crypto.privateDecrypt(
  { key: privPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  encKeyBuf
);

const getFixedAESKey = () => {
  if (!opts.pskFrom) return null;
  const keyBuffer = b64ToBuf(opts.pskFrom);
  if (!keyBuffer || keyBuffer.length !== 32) throw new Error('--psk-from must be base64 of 32 bytes');
  return keyBuffer;
};

const encryptBody = (plain, rsaPub, prevTokenB64 = null) => {
  if (opts.mode === 'aes') {
    const key = getFixedAESKey() || rand(32);

    const tryOnceAES = () => {
      const nonce = rand(12);
      const { enc, tag } = aesEncrypt(Buffer.from(plain, 'utf8'), key, nonce);
      const raw = Buffer.concat([nonce, enc, tag]);
      const b64 = bufToB64(raw);
      const tokenOnly = `${AES_HEADER_CHAR}|${b64}`;

      const withPSK = opts.embedPsk
        ? (tokenOnly + `\n\n${opts.pskDelim}${bufToB64(key)}`)
        : tokenOnly;

      return { tokenOnly, text: withPSK };
    };

    for (let attempt = 0; attempt < 3; attempt++) {
      const out = tryOnceAES();
      if (!prevTokenB64 || out.tokenOnly !== prevTokenB64 || attempt === 2) return { text: out.text };
    }
  }

  if (!rsaPub) throw new Error('Hybrid mode requires RSA public key');
  const tryOnceHybrid = () => {
    const aesKey = rand(32);
    const nonce = rand(12);
    const ek = rsaWrapAesKey(aesKey, rsaPub);
    const { enc, tag } = aesEncrypt(Buffer.from(plain, 'utf8'), aesKey, nonce);
    const token = buildHybridToken({ nonce, ek, enc, tag });
    return token;
  };
  for (let attempt = 0; attempt < 3; attempt++) {
    const token = tryOnceHybrid();
    if (!prevTokenB64 || token !== prevTokenB64 || attempt === 2) return { text: token };
  }
  throw new Error('Unexpected: rotation produced identical token repeatedly');
};

const tryDecryptFromComment = (body, rsaPriv) => {
  const found = findCryptoToken(body);
  if (!found) return { ok: false, reason: 'no-b64-token' };

  if (found.kind === 'hybrid') {
    const parsed = parseHybridTokenB64(found.token);
    if (!parsed.ok) return { ok: false, reason: 'parse-failed:' + parsed.err };
    const { nonce, ek, cipher, tag } = parsed;
    try {
      if (!rsaPriv) return { ok: false, reason: 'rsa-priv-missing' };
      const aesKey = rsaUnwrapAesKey(ek, rsaPriv);
      if (aesKey.length !== 32) return { ok: false, reason: 'bad-unwrapped-key' };
      const dec = aesDecrypt(cipher, tag, aesKey, nonce);
      return { ok: true, plaintext: dec.toString('utf8'), mode: 'hybrid', tokenStart: found.start };
    } catch (error) {
      return { ok: false, reason: 'decrypt-failed:' + error.message };
    }
  }

  if (found.kind === 'aes') {
    const tokenStr = found.token;
    const barIdx = tokenStr.indexOf('|');
    if (barIdx <= 0 || barIdx >= tokenStr.length - 1) {
      return { ok: false, reason: 'aes-bad-header' };
    }
    const header = tokenStr.slice(0, barIdx);
    const b64 = tokenStr.slice(barIdx + 1);
    if (header !== AES_HEADER_CHAR) {
      return { ok: false, reason: 'aes-unknown-header' };
    }
    if (!isB64Token(b64)) {
      return { ok: false, reason: 'aes-bad-b64' };
    }
    const buffer = b64ToBuf(b64);
    if (!buffer || buffer.length < 12 + 16 + 1) {
      return { ok: false, reason: 'aes-raw-too-short' };
    }

    const nonce = buffer.subarray(0, 12);
    const ctTag = buffer.subarray(12);
    const tag = ctTag.subarray(ctTag.length - 16);
    const cipher = ctTag.subarray(0, ctTag.length - 16);

    let keyBuf = null;
    if (opts.pskFrom) {
      keyBuf = getFixedAESKey();
    } else {
      const pskB64 = extractPSKAfter(body, found.end);
      if (!pskB64) return { ok: false, reason: 'aes-psk-missing' };
      keyBuf = b64ToBuf(pskB64);
    }
    if (!keyBuf || keyBuf.length !== 32) {
      return { ok: false, reason: 'aes-psk-bad' };
    }

    try {
      const dec = aesDecrypt(cipher, tag, keyBuf, nonce);
      return { ok: true, plaintext: dec.toString('utf8'), mode: 'aes', tokenStart: found.start };
    } catch (error) {
      return { ok: false, reason: 'aes-decrypt-failed:' + error.message };
    }
  }

  return { ok: false, reason: 'unknown-token-kind' };
};

let tokenState = { access_token: null, expires_at: 0 };

const redditAccessTokenFromRefresh = async () => {
  const now = Date.now();
  if (tokenState.access_token && now < tokenState.expires_at - 10_000) return tokenState.access_token;

  const form = new URLSearchParams();
  form.set('grant_type', 'refresh_token');
  form.set('refresh_token', opts.refreshToken);

  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${opts.clientId}:${opts.clientSecret}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': UA
    },
    body: form
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token refresh error ${res.status}: ${text}`);
  }
  const json = await res.json();
  tokenState.access_token = json.access_token;
  tokenState.expires_at = Date.now() + (json.expires_in * 1000);
  return tokenState.access_token;
};

const rfetch = async (endpoint, { method = 'GET', params = null, body = null, form = null } = {}, retry = 0) => {
  const access = await redditAccessTokenFromRefresh();
  let url = endpoint.startsWith('http') ? endpoint : (API_BASE + endpoint);
  if (params) {
    const qs = new URLSearchParams(params);
    url += (url.includes('?') ? '&' : '?') + qs.toString();
  }
  const headers = { Authorization: `Bearer ${access}`, 'User-Agent': UA, 'Accept': 'application/json' };
  let fetchBody;
  if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    fetchBody = new URLSearchParams(form);
  } else if (body) {
    headers['Content-Type'] = 'application/json';
    fetchBody = JSON.stringify(body);
  }

  if (opts.verbose) console.log('HTTP', method, url);
  const res = await fetch(url, { method, headers, body: fetchBody });

  if (res.status === 429 || res.status === 502 || res.status === 503) {
    const wait = Math.min(30_000, opts.backoffBaseMs * Math.pow(2, retry));
    if (opts.verbose) console.log('Backoff', res.status, 'wait', wait);
    await sleep(wait);
    if (retry < 5) return rfetch(endpoint, { method, params, body, form }, retry + 1);
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status} ${method} ${url}: ${text}`);
  }
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  if (ct.includes('application/json')) return res.json();
  const text = await res.text();
  throw new Error(`Expected JSON but got '${ct || 'unknown'}' from ${url}. First 200 chars:\n${text.slice(0, 200)}`);
};

const getMe = async () => rfetch('/api/v1/me');

const listMyCommentsRaw = async (username, after = null, limit = 100) =>
  rfetch(`/user/${encodeURIComponent(username)}/comments/.json`, {
    params: { limit: String(limit), sort: 'new', raw_json: '1', after: after || '', include_over_18: '1' }
  });

const listMyOverviewRaw = async (username, after = null, limit = 100) =>
  rfetch(`/user/${encodeURIComponent(username)}/overview/.json`, {
    params: { limit: String(limit), sort: 'new', raw_json: '1', after: after || '', include_over_18: '1' }
  });

const listMyComments = async (username, after = null, limit = 100) => {
  const page = await listMyCommentsRaw(username, after, limit);
  if (Array.isArray(page?.data?.children) && page.data.children.length > 0) return page;
  const overview = await listMyOverviewRaw(username, after, limit);
  if (Array.isArray(overview?.data?.children)) {
    overview.data.children = overview.data.children.filter((child) => child.kind === 't1');
    overview.data.dist = overview.data.children.length;
    return overview;
  }
  return page;
};

const editComment = async (thingId, text) => {
  const resp = await rfetch('/api/editusertext', {
    method: 'POST',
    form: { api_type: 'json', text, thing_id: thingId }
  });
  const errors = resp?.json?.errors;
  if (Array.isArray(errors) && errors.length > 0) {
    const msg = errors.map((error) => Array.isArray(error) ? error.join(':') : String(error)).join('; ');
    throw new Error(`editusertext errors: ${msg}`);
  }
  const things = resp?.json?.data?.things;
  if (!Array.isArray(things) || things.length === 0) {
    throw new Error('editusertext: no things returned (edit may have been rejected)');
  }
  return resp;
};

const parseRateLimitSeconds = (msg) => {
  if (!msg) return null;
  const needle = 'for ';
  const idx = msg.indexOf(needle);
  if (idx === -1) return null;
  let cursor = idx + needle.length;
  let buffer = '';
  while (cursor < msg.length) {
    const ch = msg[cursor];
    if (ch >= '0' && ch <= '9') { buffer += ch; cursor++; continue; }
    break;
  }
  if (!buffer) return null;
  const n = Number(buffer);
  return Number.isFinite(n) ? n : null;
};

const editCommentWithRetry = async (thingId, text) => {
  let retries = 0;
  for (;;) {
    try {
      const resp = await editComment(thingId, text);
      return { resp, retries };
    } catch (error) {
      const msg = String(error && error.message || '');
      if (msg.includes('RATELIMIT')) {
        if (retries >= (opts.maxEditRetries || 0)) throw error;
        const seconds = parseRateLimitSeconds(msg);
        const baseMs = typeof seconds === 'number' ? (seconds * 1000) : (opts.backoffBaseMs * Math.pow(2, retries));
        const wait = Math.min(60_000, baseMs + 250 + Math.floor(Math.random() * 500));
        if (opts.verbose) console.log(`RATELIMIT hit; retry ${retries + 1}/${opts.maxEditRetries} after ${wait}ms`);
        await sleep(wait);
        retries++;
        continue;
      }
      throw error;
    }
  }
};

const getCommentById = async (thingId) => rfetch('/api/info', { params: { id: thingId, raw_json: '1' } });

const containsRe = compileRegex(opts.contains);
const notContainsRe = compileRegex(opts.notContains);

const shouldIncludeComment = (comment) => {
  const subreddit = comment.subreddit;
  if (opts.onlySubs) {
    const set = new Set(opts.onlySubs.split(',').map((name) => name.trim().toLowerCase()).filter(Boolean));
    if (!set.has(subreddit.toLowerCase())) return false;
  }
  if (opts.skipSubs) {
    const set = new Set(opts.skipSubs.split(',').map((name) => name.trim().toLowerCase()).filter(Boolean));
    if (set.has(subreddit.toLowerCase())) return false;
  }
  if (!withinDate(comment.created_utc, opts.start, opts.end)) return false;
  if (Number.isFinite(opts.minScore) && comment.score < opts.minScore) return false;
  if (Number.isFinite(opts.maxScore) && comment.score > opts.maxScore) return false;
  if (containsRe && !containsRe.test(comment.body || '')) return false;
  if (notContainsRe && notContainsRe.test(comment.body || '')) return false;
  return true;
};

const headerLine = (entry) => {
  const ts = new Date((entry.created_utc || 0) * 1000).toISOString();
  let line = `${entry.thing_id || ''} ${entry.subreddit || ''} ${ts} ${entry.action || ''}${entry.op ? ' state=' + entry.op : ''}${entry.link_id ? ' link=' + entry.link_id : ''}`;
  return line;
};

const logLine = (entry) => {
  let line = headerLine(entry);
  if (entry.url) line += `\n  URL: ${entry.url}`;
  if (entry.preview_from) line += `\n  FROM: ${oneLine(entry.preview_from)}`;
  if (entry.op === 'rotate' && entry.plaintext) line += `\n  PLAINTEXT: ${oneLine(entry.plaintext)}`;
  if (entry.preview_to) line += `\n  TO  : ${oneLine(entry.preview_to)}`;
  if (entry.error) line += `\n  ERROR: ${entry.error}`;
  if (entry.verify_after) line += `\n  VERIFY: ${entry.verify_after}`;
  if (entry.note) line += `\n  NOTE: ${entry.note}`;
  if (entry.edited === true) line += `\n  EDITED: yes`;
  if (entry.edited === false) line += `\n  EDITED: no`;
  return line;
};

const buildConfigSnapshot = () => {
  return {
    mode: opts.mode,
    embedPsk: opts.embedPsk,
    pskDelim: opts.pskDelim,
    pskFrom: opts.pskFrom || null,
    keyDir: opts.keyDir,
    keyId: opts.keyId || null,

    start: opts.start || null,
    end: opts.end || null,
    onlySubs: opts.onlySubs || null,
    skipSubs: opts.skipSubs || null,
    minScore: Number.isFinite(opts.minScore) ? opts.minScore : null,
    maxScore: Number.isFinite(opts.maxScore) ? opts.maxScore : null,
    contains: opts.contains || null,
    notContains: opts.notContains || null,
    limit: Number.isFinite(opts.limit) ? opts.limit : null,
    maxEdits: Number.isFinite(opts.maxEdits) ? opts.maxEdits : null,

    onlyPlain: !!opts.onlyPlain,
    restore: !!opts.restore,
    restoreFrom: opts.restoreFrom || null,
    backupPath: opts.backupPath || null,
    resumeFile: opts.resumeFile || null,

    wordListPath: opts.wordListPath || null,
    prefix: opts.prefix || null,
    prefixLen: opts.prefixLen || null,
    prefixSentences: opts.prefixSentences || null,
    prefixCommaP: typeof opts.prefixCommaP === 'number' ? opts.prefixCommaP : null,
    postfix: opts.postfix || null,

    executionConcurrency: opts.concurrency,
    jitterMs: opts.jitterMs,
    backoffBaseMs: opts.backoffBaseMs,
    maxEditRetries: opts.maxEditRetries,

    verifyAfter: !!opts.verifyAfter,
    consoleLog: !!opts.consoleLog,
    verbose: !!opts.verbose,

    planPath: opts.planPath || null,
    executePath: opts.executePath || null
  };
};

const postWebhookSummary = async (phase, username, stats) => {
  if (!opts.webhook) return;

  const payload = {
    phase,
    username,
    timestamp: new Date().toISOString(),
    ...stats,
    config: buildConfigSnapshot()
  };

  try {
    if (opts.verbose) {
      console.log('Webhook POST payload:', JSON.stringify(payload, null, 2));
    }
    const res = await fetch(opts.webhook, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': UA
      },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const text = await res.text();
      if (opts.verbose) {
        console.warn('Webhook POST failed:', res.status, text.slice(0, 200));
      }
    } else if (opts.verbose) {
      console.log('Webhook POST succeeded with status', res.status);
    }
  } catch (error) {
    if (opts.verbose) {
      console.warn('Webhook POST error:', error.message);
    }
  }
};

const permalinkOf = (comment) => {
  const p = comment.permalink || '';
  if (!p) return '';
  return p.startsWith('http') ? p : ('https://www.reddit.com' + p);
};

const promisePool = async (items, limit, worker) => {
  const results = [];
  let index = 0;
  let active = 0;
  return await new Promise((resolve) => {
    const next = () => {
      if (index === items.length && active === 0) return resolve(results);
      while (active < limit && index < items.length) {
        const idx = index++; active++;
        Promise.resolve(worker(items[idx], idx))
          .then((res) => { results[idx] = res; active--; next(); })
          .catch((err) => { results[idx] = { error: err.message }; active--; next(); });
      }
    };
    next();
  });
};

const executePlanFile = async (planPath, username) => {
  const fp = path.resolve(planPath);
  if (!fs.existsSync(fp)) {
    throw new Error(`Plan file not found: ${fp}`);
  }
  const raw = fs.readFileSync(fp, 'utf8');
  let plan;
  try {
    plan = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Failed to parse plan JSON: ${error.message}`);
  }
  if (!Array.isArray(plan)) {
    throw new Error('Plan JSON must be an array');
  }

  let edited = 0;
  const logs = [];
  const backups = [];

  const worker = async (entry) => {
    const thingId = entry.thing_id || entry.id;
    const outText = entry.to;
    const body = entry.from || '';
    const base = {
      id: entry.id || '',
      thing_id: thingId || '',
      link_id: entry.link_id || '',
      url: entry.url || '',
      subreddit: entry.subreddit || '',
      created_utc: entry.created_utc || 0,
      score: entry.score,
      action: entry.action || 'execute-plan',
      op: entry.op || null,
      plaintext: entry.plaintext || '',
      preview_from: body,
      preview_to: outText || ''
    };

    if (!thingId) {
      logs.push({ ...base, edited: false, error: 'missing thing_id' });
      return;
    }
    if (typeof outText !== 'string' || !outText.length) {
      logs.push({ ...base, edited: false, error: 'empty "to" field in plan entry' });
      return;
    }
    if (outText.length > REDDIT_COMMENT_MAX) {
      logs.push({ ...base, edited: false, error: `encrypted-body-too-long(${outText.length})` });
      return;
    }

    if (opts.maxEdits && edited >= opts.maxEdits) {
      logs.push({ ...base, edited: false, note: 'max-edits-reached (skipped actual edit)' });
      return;
    }

    if (opts.backupPath) {
      backups.push({ thing_id: thingId, id: entry.id || '', subreddit: entry.subreddit || '', created_utc: entry.created_utc || 0, body });
    }

    await sleep(jitter(opts.jitterMs));
    try {
      const { retries } = await editCommentWithRetry(thingId, outText);
      edited++;
      const logEntry = {
        ...base,
        edited: true,
        note: (retries && retries > 0) ? `retries:${retries}` : base.note
      };
      logs.push(logEntry);

      if (opts.verifyAfter) {
        await sleep(600);
        const verify = await getCommentById(thingId);
        const bodyNow = verify?.data?.children?.[0]?.data?.body || '';
        const ok = bodyNow === outText;
        logs.push({ id: entry.id || '', thing_id: thingId, verify_after: ok ? 'ok' : 'mismatch' });
      }
    } catch (error) {
      logs.push({ ...base, edited: false, error: error.message });
    }
  };

  await promisePool(plan, opts.concurrency, worker);

  if (opts.consoleLog && logs.length) {
    const human = logs.map((logEntry) => logLine(logEntry)).join('\n\n');
    console.log(human);
  }

  if (opts.backupPath && backups.length) {
    fs.writeFileSync(opts.backupPath, JSON.stringify(backups, null, 2), { mode: 0o600 });
    console.log(`Backup written: ${opts.backupPath}`);
  }

  const failed = logs.filter((entry) => entry.edited === false).length;
  const verifyMismatches = logs.filter((entry) => entry.verify_after === 'mismatch').length;

  console.log(`Plan entries: ${plan.length} | Edited: ${edited} | Failed: ${failed}`);

  await postWebhookSummary({
    phase: 'execute',
    username: username || null,
    planEntries: plan.length,
    edited,
    failed,
    verifyMismatches
  });
};

(async () => {
  try {
    if (isPureExecute) {
      const me = await getMe();
      const username = me.name;
      console.log(`Logged in as: ${username}`);
      await executePlanFile(opts.executePath, username);
      return;
    }

    const { pub, priv } = loadKeyMaterial();

    const me = await getMe();
    const username = me.name;
    console.log(`Logged in as: ${username}`);

    let backupMap = new Map();
    if (opts.restoreFrom) {
      const backupJson = JSON.parse(fs.readFileSync(opts.restoreFrom, 'utf8'));
      for (const row of backupJson) backupMap.set(row.thing_id, row.body);
    }

    const logs = [];
    const plans = [];
    let fetched = 0;
    let plannedEdits = 0;

    let after = null;
    if (opts.resumeFile && fs.existsSync(opts.resumeFile)) {
      try { const resumeJson = JSON.parse(fs.readFileSync(opts.resumeFile, 'utf8')); after = resumeJson.after || null; } catch {}
    }

    outer:
    while (true) {
      const page = await listMyComments(username, after, 100);
      const children = page?.data?.children || [];
      if (opts.verbose) console.log(`Fetched page: children=${children.length} after=${page?.data?.after || null}`);
      if (children.length === 0) break;

      if (opts.limit && fetched + children.length > opts.limit) {
        children.length = Math.max(0, opts.limit - fetched);
      }

      const scan = children.map((child) => child.data);
      const work = scan.filter((comment) => shouldIncludeComment(comment));
      fetched += children.length;
      if (opts.verbose) console.log(`Page stats: scanned=${scan.length} kept=${work.length}`);

      const worker = async (comment) => {
        const body = comment.body || '';
        const foundTok = findCryptoToken(body);
        const firstTok = foundTok ? foundTok.token : null;
        const tokenStart = foundTok ? foundTok.start : -1;

        let action = null;
        let outText = null;
        let willEdit = false;
        let decPlain = null;

        if (comment.archived) {
          logs.push({
            id: comment.id,
            thing_id: comment.name,
            link_id: comment.link_id || '',
            url: permalinkOf(comment),
            subreddit: comment.subreddit,
            created_utc: comment.created_utc,
            score: comment.score,
            action: 'skip-archived'
          });
          return;
        }

        if (opts.restoreFrom) {
          const orig = backupMap.get(comment.name);
          if (orig != null) { outText = orig; action = 'restore-from-backup'; willEdit = true; }
          else { action = 'skip-no-backup'; }
        } else if (opts.restore) {
          if (!firstTok) action = 'skip-plain(--restore)';
          else {
            const dec = tryDecryptFromComment(body, priv);
            if (dec.ok) { outText = dec.plaintext; action = 'restore:decrypt->plaintext'; willEdit = true; }
            else action = `skip-undecipherable(--restore:${dec.reason})`;
          }
        } else if (firstTok) {
          if (opts.onlyPlain) action = 'skip-already-encrypted(--only-plain)';
          else {
            const decInfo = tryDecryptFromComment(body, priv);
            if (decInfo.ok) {
              decPlain = decInfo.plaintext;
              const prevTok = firstTok;
              const re = encryptBody(decInfo.plaintext, pub, prevTok);
              const existingPrefix = tokenStart > 0 ? body.slice(0, tokenStart).trimEnd() : '';
              outText = existingPrefix ? (existingPrefix + '\n\n' + re.text) : re.text;
              action = `re-encrypt:${decInfo.mode}->${opts.mode}${opts.mode === 'aes' && opts.embedPsk ? '(embed-psk)' : ''}`;
              willEdit = true;
            } else {
              action = `skip-undecipherable(${decInfo.reason})`;
            }
          }
        } else {
          const en = encryptBody(body, pub, null);
          const prefixBlock = buildPrefixBlock();
          outText = prefixBlock ? (prefixBlock + '\n\n' + en.text) : en.text;

          action = `encrypt:${opts.mode}${opts.mode === 'aes' && opts.embedPsk ? '(embed-psk)' : ''}`;
          willEdit = true;
        }

        const opState = action && (action.startsWith('encrypt:') ? 'fresh'
          : action.startsWith('re-encrypt:') ? 'rotate'
          : (action === 'restore-from-backup' || action.startsWith('restore:')) ? 'restore'
          : null);

        if (opts.verbose) {
          const iso = new Date((comment.created_utc || 0) * 1000).toISOString();
          const permalink = permalinkOf(comment);
          console.log(`PLAN thing=${comment.name} id=${comment.id} link=${comment.link_id || ''} date=${iso} url=${permalink}`);
          console.log(`ACTION: ${action} state=${opState || 'n/a'}`);
          console.log('FROM:', oneLine(body));
          if (opState === 'rotate' && decPlain != null) console.log('PLAINTEXT:', oneLine(decPlain));
          console.log('TO  :', oneLine(outText || ''));
        }

        if (opts.postfix && willEdit && action && (action.startsWith('encrypt:') || action.startsWith('re-encrypt:'))) {
          outText = (outText || '') + '\n\n' + String(opts.postfix);
        }

        const entry = {
          id: comment.id,
          thing_id: comment.name,
          link_id: comment.link_id || '',
          url: permalinkOf(comment),
          subreddit: comment.subreddit,
          created_utc: comment.created_utc,
          score: comment.score,
          action,
          op: opState,
          plaintext: decPlain || '',
          preview_from: body,
          preview_to: outText || ''
        };

        if (!willEdit) {
          logs.push(entry);
          return;
        }

        if (opts.maxEdits && plannedEdits >= opts.maxEdits) {
          logs.push({ ...entry, note: 'max-edits-reached (skipped planning for this comment)' });
          return;
        }

        if (outText.length > REDDIT_COMMENT_MAX) {
          logs.push({
            ...entry,
            edited: false,
            error: `encrypted-body-too-long(${outText.length}) suggest-hybrid-if-not`
          });
          return;
        }

        if (opts.planPath || opts.executePath) {
          plans.push({
            id: comment.id,
            thing_id: comment.name,
            link_id: comment.link_id || '',
            url: permalinkOf(comment),
            subreddit: comment.subreddit,
            created_utc: comment.created_utc,
            score: comment.score,
            action,
            op: opState,
            plaintext: decPlain || '',
            from: body,
            to: outText
          });
        }

        plannedEdits++;
        logs.push(entry);
      };

      await promisePool(work, opts.concurrency, worker);

      after = page.data.after;
      if (opts.resumeFile) {
        try { fs.writeFileSync(opts.resumeFile, JSON.stringify({ after }, null, 2)); } catch {}
      }

      if (!after) break;
      if (opts.limit && fetched >= opts.limit) break outer;
      if (opts.maxEdits && plannedEdits >= opts.maxEdits) break outer;
    }

    if (opts.consoleLog && logs.length) {
      const human = logs.map((logEntry) => logLine(logEntry)).join('\n\n');
      console.log(human);
    }

    if ((opts.planPath || opts.executePath) && plans.length) {
      const planFile = opts.planPath || opts.executePath;
      fs.writeFileSync(planFile, JSON.stringify(plans, null, 2), { mode: 0o600 });
      console.log(`Plan JSON written: ${planFile} (entries=${plans.length})`);
    } else if (opts.planPath && !plans.length) {
      console.log('No edits planned; plan file not written (plan would be empty).');
    }

    const planningErrors = logs.filter((entry) => entry.error).length;

    console.log(`Fetched: ${fetched} | Planned edits: ${plannedEdits} | Planning errors: ${planningErrors}`);

    await postWebhookSummary({
      phase: 'plan',
      username,
      fetched,
      planned: plannedEdits,
      planEntries: plans.length,
      failed: planningErrors
    });

    if (opts.executePath) {
      const execFile = opts.executePath || opts.planPath;
      await executePlanFile(execFile, username);
    }
  } catch (error) {
    console.error('Fatal:', error.stack || error.message);
    process.exit(1);
  }
})();
