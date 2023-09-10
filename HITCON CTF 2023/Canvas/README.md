# Canvas

* Category: Web
* Score: 400/500
* Solves: 4

## Description

A safer and faster alternative to [Dwitter](https://www.dwitter.net/).

## Running the challenge

When testing challenge locally, please create a `.env` file with `SITE=http://web` before docker compose up -d.

## Overview

You have a direct JavaScript code execution in a within a jain inside a web worker. The target is to somehow steal the flag from `localStorage`.

## Solution

### Escaping JS Jail

There are probably many ways to do it. The eastiest one is to get the global from `this` of a new function:

```javascript
(function(){ throw { message: this } })()
```

another way is to abuse [V8 Stack Trace API](https://v8.dev/docs/stack-trace-api):

```javascript
try {
	null.f()
} catch (e) {
	TypeError = e.constructor
}
Error = TypeError.prototype.__proto__.constructor
Error.prepareStackTrace = (err, structuredStackTrace) => structuredStackTrace
try{
	null.f()
} catch(e) {
	const g = e.stack[2].getFunction().arguments[0].target
	if (g) { throw { message: g } }
}
```

both of them will show a `[object DedicatedWorkerGlobalScope]`, which is a global object of a web worker.

> BTW, I didn't catch the easier one before the CTF :cry:
> Only the stack trace api is my intended solution.

### Escaping Web Worker

Arbitrary code execution in a web worker doesn't give you a way to access `localStorage`, so you still need to get out of it.

The fact that web worker isn't a secure way to sandbox JavaScript code is because it still same-origin as the main page, so you can still do a lot of things like `fetch` easily. But that's is completely useless here as this challenge is actually a static website, there is no server-side logic to exploit :P

Another thing that you can do with this same-origin privilege is to create an object url with `URL.createObjectURL`, and the created url still has the same origin as the main page. For example, running the following code would create a URL like `blob:https://chal-canvas.chal.hitconctf.com/17a33cd9-ca3d-40a5-9944-4a18119aa576`.

```javascript
(function(){
	const u = this.URL.createObjectURL(new this.Blob(['<h1>peko</h1>'], { type: 'text/html' }))
	throw { message: u }
})()
```

Visiting that url will show you a page with a big, bold **peko** text on it, and you can open the console to check the origin is still the same.

So you may think, is it possible to leak this url to attacker's server somehow (or is it even possible?), and let the attacker's server redirect to it? Actually trying to do so will show it is not really possible as Chromium treat `blob:` url as local resource (like `file:`), so you won't be able to negivate to it from a different origin.

Using `Location` header to do that would result in `ERR_UNSAFE_REDIRECT`, and using JavaScript would result in `Not allowed to load local resource: blob:...`

This is why there is convenient sanitized HTML injection:

```javascript
worker.addEventListener('message', function (event) {
	if (event.data.type === 'error') {
		document.getElementById('error-output').setHTML(event.data.content)
	}
})
```

[`setHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTML) is a part of [HTML Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API), and you can see that `meta` tag is allowed in their [default allowlist](https://wicg.github.io/sanitizer-api/#baseline-elements). So this mean you use `meta` tag to redirect to the blob url. Since this navigation is from same-origin, it will work.

```javascript
(function(){
	const u = this.URL.createObjectURL(new this.Blob(['<h1>peko</h1>'], { type: 'text/html' }))
	this.postMessage({ type: 'error', content: 'hello' + '<meta http-equiv="refresh" content="0; url=' + u + '">' })
})()
```

### Bypassing CSP

Now you can have arbitrary HTML displayed on the same origin, but blob URL still inherit the CSP policy so you still need to find a way around it:

```csp
default-src 'self' 'unsafe-eval'
```

There isn't much possibility to try as there is only two scripts: `main.js` and `worker.js`. Apparently `main.js` is not exploitable, so the only candidate is `worker.js`.

Thanks to the similarity between worker globals and window globals, `worker.js` actually works just fine when being included in window context, so all you need is to `postMessage` from another window and bypass the JS jail again to get XSS.

### Getting the flag

From the bot's source code, we know the flag is in `localStorage.savedCode`, but it will be overwritten when it is executing new code using `/?code=...`. Fortunately, the flag is still the `fallback` variable, so just play with window references a bit and access the flag with `eval("fallback")`.

[exp.html](./exp/exp.html) is my original exploit, and [exp2.html](./exp/exp2.html) is a simplified exploit.
