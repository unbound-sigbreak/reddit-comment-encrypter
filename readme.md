# Reddit Comment Encryptor / Rotator / Restorer

**AES-256-GCM or Hybrid RSA+AES comment overwriter with prefix/postfix support**

One-liner: Traverses **your** Reddit comment history and overwrites each body **in place** with authenticated ciphertext. Supports rotation, restore, backups, prefix/postfix, filtering, and concurrency.
Edits always go through a **plan file**.

---

## What this tool actually does

* Fetches **your** comments via OAuth.
* For each comment (depending on filters):

  * If plain → **encrypt** and overwrite.
  * If already encrypted → **decrypt**, re-encrypt (fresh nonce), overwrite.
  * If `--restore` → decrypt and restore plaintext.
  * If `--restore-from file` → restore original body from backup snapshot.
* Every edit is performed through a **JSON plan**:
  `--plan` generates → `--execute` applies.

This tool **reduces scrapers’ ability to mine your text** but does **not** defeat Reddit admins (they can restore).

---

## Encryption modes

### AES-256-GCM (`--mode aes`)

* 32-byte key, 12-byte nonce, 16-byte auth-tag.
* Output token starts with a **1-byte header**:

  ```
  A|<base64( iv(12) || ciphertext || tag )>
  ```
* If you manually strip `A|`, the **raw base64** works in with Web AES page: https://unbound-sigbreak.github.io/message-deencrypter/.
* Keying:

  * Default: random 32-byte key **per comment**.
  * `--psk-from <b64-32>`: fixed PSK for all AES comments (restorable).
  * `--embed-psk`: append PSK as base64 immediately beneath token
    `AES-PSK:<base64>`.
  * `--psk-delim` customizes that prefix.

### Hybrid RSA+AES (`--mode hybrid`)

* Random 32-byte AES key per comment.
* AES key wrapped using RSA-OAEP-SHA256.
* Token is an RCMT binary header encoded as base64.
* Requires your private key to rotate/restore.

### Detection

* Tool scans every whitespace-delimited token.
* Recognizes:

  * AES: exactly `A|<base64>`.
  * Hybrid: base64-looking token with `RCMT` magic after decode.

---

## Prefix + Postfix (optional)

### Prefix (before token)

Two layers:

1. **Literal prefix**: `--prefix "text"`
2. **Generated prefix** (word-salad) if desired:

   * `--prefix-sentences min,max`
   * `--prefix-len min,max` (characters)
   * `--wordlist words.json`
   * `--prefix-comma-p p`

Order:

```
[prefix literal]
(blank)
[prefix generated]
(blank)
A|...
AES-PSK:...
```

### Postfix (after token / PSK)

* Added **only** for fresh encrypts and re-encrypts.
* Positioned two newlines below the token/PSK.
* `--postfix "text"`

Example:

```
Human-like intro paragraph.

A|rmkJh8Kk5... (ciphertext)
AES-PSK:0rF+...

This is the postfix footer.
```

---

## Plan / Execute workflow

**Always produces or consumes a JSON plan.**

### 1) PLAN (no edits)

```
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --mode aes --plan plan.json [other flags...]
```

This:

* Fetches your comments.
* Decides what would be edited.
* Writes `plan.json`.

### 2) EXECUTE (apply plan)

```
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --execute plan.json
```

### Combined plan+execute

```
./index.js ... --plan plan.json --execute plan.json
```

### Default

If you omit **both** `--plan` and `--execute`, it automatically sets:

```
--plan ./reddit-crypt-plan.json
```

---

## Restore modes

### Decrypt & restore plaintext (`--restore`)

Works when:

* AES comment has a recoverable key
  (`--psk-from` or `--embed-psk`).
* Hybrid comment can be decrypted with your RSA private key.

### Restore from backup snapshot (`--restore-from backup.json`)

* Overrides crypto.
* Restores exact previous bodies from snapshot file.

### Backup

```
--backup backup.json
```

Executed during runs that perform edits.

---

## Filters

* `--start <ISO>` / `--end <ISO>`
* `--only-subreddits a,b`
* `--skip-subreddits x,y`
* `--min-score N` / `--max-score N`
* `--contains "regex"` / `--not-contains "regex"`
* `--limit N` limit total fetched
* `--only-plain` do not re-encrypt existing ciphertext

---

## Networking / pacing / retries

* `--concurrency N` worker pool for encryption planning **and** execution.
* `--jitter-ms min,max` human-like editing delay.
* `--backoff-base-ms ms`
* `--max-edit-retries N` handles Reddit’s JSON-level RATELIMIT returns.
* `--verify-after` refetches comment after editing and compares.

---

## Logging

Human-readable structured logs contain:

* Comment IDs / link IDs
* URL, subreddit, timestamp, score
* ACTION:
  `encrypt:aes`, `re-encrypt:aes->aes`, `restore:...`, `skip-...`
* STATE: `fresh`, `rotate`, `restore`
* FROM → TO bodies
* For rotations: decrypted PLAINTEXT
* RATELIMIT retries
* VERIFY results
* Errors

`--console` prints the planning/execution log to stdout.

---

## Usage examples

### AES + embedded PSK + prefixes

```
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --mode aes --embed-psk \
  --prefix "Hello friend," \
  --postfix "Regards, me." \
  --prefix-sentences 2,4 --wordlist words.json \
  --plan plan.json --console
```

### Hybrid encryption with backup + verification

```
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --mode hybrid --key-dir ~/.keys --key-id mykey \
  --backup backup.json --verify-after \
  --plan plan.json --execute plan.json
```

## Webhook summary (optional)

You can have the tool POST a JSON summary when a run completes.

Enable it with:

```bash
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --mode aes \
  --plan plan.json --execute plan.json \
  --webhook "https://example.com/reddit-crypt-summary"
```

### Restore decryptable comments

```
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --restore --verify-after --plan restore.json
```

### Restore from backup snapshot

```
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --restore-from backup.json --plan restore.json
```

### Fixed PSK (no key embedding)

```
./index.js \
  --client-id <id> --client-secret <secret> --refresh-token <rt> \
  --mode aes --psk-from <base64-32> \
  --plan plan.json
```

---

## AES token format details

```
A|BASE64
```

Where:

```
BASE64 = base64( iv(12 bytes) || ciphertext || tag(16 bytes) )
```

* Manual removal of the `A|` header yields the base64 blob that your Web AES tool accepts.
* If `--embed-psk` is used, PSK follows on the next line:

  ```
  AES-PSK:<base64-32>
  ```

---

## Hybrid token format (unchanged)

```
base64(
  MAGIC "RCMT" |
  VERSION(0x01) |
  MODE(0x02 HYBRID) |
  FLAGS(1B) |
  NONCE_LEN(1B) |
  EK_LEN(2B) |
  NONCE |
  RSA_WRAPPED_AES_KEY |
  CIPHER_LEN(4B) |
  CIPHER |
  TAG(16B)
)
```

---

## Caveats

* Reddit administrators with edit-history access can restore plaintext.
* Scrapers that archived your comments before encryption will still have plaintext.
* Very long plaintext/comments may exceed `~10k` limit after encryption.
* AES mode without `--embed-psk` or `--psk-from` is **irreversible** unless you have a backup.
* Prefix/postfix increase comment size; monitor limits.

---

## Requirements

* Node **22+**
* Refresh token with scopes: `identity`, `edit`, `history`, `read`
* For hybrid mode: RSA-OAEP-SHA256 keypair.



### Docker update:

```
docker build -t reddit-comment-encrypter .

docker tag reddit-comment-encrypter DOMAIN.xyz/USERNAME/reddit-comment-encrypter:latest
docker tag reddit-comment-encrypter DOMAIN.xyz/USERNAME/reddit-comment-encrypter:v0.0.X
docker push DOMAIN.xyz/USERNAME/reddit-comment-encrypter:latest
docker push DOMAIN.xyz/USERNAME/reddit-comment-encrypter:v0.0.X

docker pull DOMAIN.xyz/USERNAME/reddit-comment-encrypter:latest
```