# Private Browsing+

* Category: Web
* Score: 450/500
* Solves: 2

## Description

This is a proxy to your favorite websites that automatically strips unnecessary annoyances. It is a complete rewrite of [Private Browsing](../../AIS3%20Pre-exam%202022/Private%20Browsing/).

## Overview

The web service allows you to create a reverse proxy to arbitrary website under `/~$name/` with a lot of filters to prevent XSS, but the target is to bypass all of them and get XSS and capture the flag.

## Solution

### Render arbitrary HTML on the target origin

Since the `viewer.js` always sanitize the incoming HTML using DOMPurify, it can't render arbitrary HTML unless you can find a DOMPurify 0day, so you have to find a way around it.

The intended vulnerabilty is due to `/~$name/real/path` returns different types of response depends on fetch metadata headers:

```javascript
if (
    req.headers['sec-fetch-mode'] &&
    req.headers['sec-fetch-mode'] !== 'navigate' &&
    req.headers['sec-fetch-site'] === 'same-origin'
) {
    req.url = chunks.slice(2).join('/')
    proxy.handler(req, res)
} else {
    res.writeHead(200, { ...DEFAULT_HEADERS, 'content-type': 'text/html' })
    res.end(VIEWER_HTML.replace('SITEB64', btoa(proxy.site)))
}
```

Note that while the proxy blocks any caching, Chromium still have a disk cache used for navigations. So use can use the trick originated from [SECCON CTF 2022 Quals - spannote](https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote) to let Chromium render the cached response on its own.

### Bypass CSP with response splitting

This challenge define a CSP policy of:

```
default-src 'self'; style-src 'unsafe-inline' *; img-src *; font-src *; frame-src 'self' data:
```

So we have to serve a js somewhere in the same origin, but js files are blocked by this:

```javascript
responseHook: (ctx, req, res) => {
    // omitted...
    if (
        res.headers['content-type'].toLowerCase().includes('script') ||
        req.headers['sec-fetch-dest'] === 'script'
    ) {
        res.headers['content-length'] = '0'
        delete res.headers['transfer-encoding']
    }
    // omitted...
}
```

but if you look at how it does proxying more closely, it is easy to see that it still pipes the response body to the client even if the CL are set to 0:

```javascript
const proxyReq = request(reqObj, proxyRes => {
    if (responseHook) {
        responseHook(ctx, reqObj, proxyRes)
    }
    res.writeHead(proxyRes.statusCode, proxyRes.statusMessage, proxyRes.headers)
    proxyRes.pipe(res)
    proxyRes.on('error', err => {
        console.error('proxyRes error', err)
    })
})
```

So if we can get Chromium to reuse the same socket for two `script` requests, we may make the response body looks like a HTTP response on its own, then the second request would success and script are executed. This is called response splitting.

Forcing Chromium to attempt to reuse same socket is easy: just fill the socket pool as max sockets per origin is 6 by default, so embedding more than 6 `<script>` tags in the HTML would do the trick. However, actually doing so would not work as expected.

The main blocker to this is that Chromium doesn't like extra data after response body, and the relevant check is done [here](https://source.chromium.org/chromium/chromium/src/+/main:net/http/http_stream_parser.cc;l=1188-1208;drc=6dc3722b8b1cf47f6863a85f1d09fa64edcd8cc8). So we have to find some way to let the node.js proxy to flush the header on `res.writeHead(proxyRes.statusCode, proxyRes.statusMessage, proxyRes.headers)`, as its default behavior is to wait for the first body chunk and send the header and the chunk together.

The intended solution is to just dig into how node.js does HTTP internally find `writeHeader`, and you may find this line [here](https://github.com/nodejs/node/blob/ed6f45bef86134533550924baa89fd92d5b24f78/lib/_http_outgoing.js#L587) eventually:

```javascript
  // Wait until the first body chunk, or close(), is sent to flush,
  // UNLESS we're sending Expect: 100-continue.
  if (state.expect) this._send('');
```

So if our response header contains a `Expect: 100-continue`, node will flush the header immediately even without body, which is exactly what we want for exploiting response splitting on Chromium. The even funnier thing about this is that [Expect](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect) is meant to be a **Request header**, not a response header, so you might think why is it here? It turns out node.js abstract both request and response as [`OutgoingMessage`](https://github.com/nodejs/node/blob/ed6f45bef86134533550924baa89fd92d5b24f78/lib/_http_outgoing.js#L105) in [`_http_outgoing.js`](https://github.com/nodejs/node/blob/ed6f45bef86134533550924baa89fd92d5b24f78/lib/_http_outgoing.js), and the [`ServerResponse`](https://github.com/nodejs/node/blob/ed6f45bef86134533550924baa89fd92d5b24f78/lib/_http_server.js#L193C10-L193C24) inherits from `OutgoingMessage`.

Anyway, with this technique we can easily bypass the CSP and gain JavaScript execution.

### Getting the flag

The last step is to get the flag from the bot somehow, which might is not that obvious as the bot **visits submitted URL first**, then go to `/~note/` to submit the flag to a internal [note.js](./dist/web/note.js) service.

The trick here is to register a service worker using the same response splitting trick again, and add a header `Service-Worker-Allowed: /` to ensure it can control the whole origin. The the request to `/~note/` will be intercepted by the service worker, so getting the flag is trivial.

My solver: [solve.js](./solution/solve.js).
