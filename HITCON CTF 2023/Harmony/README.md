# Harmony

* Category: Web
* Score: 450/500
* Solves: 2

## Description

Harmony is the sleek and minimalist chat application poised to replace Discord, offering users a clutter-free and straightforward platform for seamless communication and collaboration.

## Overview

You need to find a way to exploit the Electron app to run `/readflag` on the bot to get flag.

## Solution

### TL;DR

* YouTube embed link processing can be exploited to embed `file://` files, not just external websites.
* Uploaded filename mismatch allows writing html files locally, not just image files.
* Electron treats `file://` as same-origin, which is not the case in browsers. So you can use `file://` to embed a local html to get access to preload and ipc.
* There is a boolean-only prototype pollution in Electron main process `set-channels` IPC handler, which can be used to pollute `sandbox: false` so that new prompts runs without sandbox.
* In the new prompt, `setHTML` still allows `meta` tar so you can do meta redirect to display external websites in that prompt window (`CI: false, SBX: false`).
* Use client-side prototype pollution to leak internal modules, and get access to Node.js modules.

### YouTube embed link processing

In [TextMessage.vue](./dist/client/src/components/TextMessage.vue), the `getYoutubeEmbedUrl` function is used to process YouTube embed links.

```typescript
function getYoutubeEmbedUrl(url: string): string | null {
	// known youtube url formats
	// https://www.youtube.com/watch?v=hI34Bhf5SaY
	// https://youtu.be/w4U9S5eX3eY
	// https://m.youtube.com/watch?v=kv4UD4ICd_0
	// https://music.youtube.com/watch?v=GL5s27qtvWw
	// https://www.youtube.com/v/ZK64DWBQNXw
	// https://m.youtube.com/v/dQw4w9WgXcQ
	// https://www.youtube.com/e/F5GjEwI8wEA
	// https://m.youtube.com/e/4daUOEfnYKI
	const parsed = new URL(url)
	if (parsed.hostname === 'youtu.be') {
		parsed.hostname = 'www.youtube.com'
		parsed.pathname = `/embed${parsed.pathname}`
		return parsed.href
	}
	const ythost = /\w+\.youtube\.com/
	if (!ythost.test(parsed.hostname)) {
		return null
	}
	parsed.hostname = parsed.hostname.replace(ythost, 'www.youtube.com')
	if (parsed.pathname === '/watch') {
		parsed.pathname = `/embed/${parsed.searchParams.get('v')}`
		parsed.search = ''
		return parsed.href
	}
	if (parsed.pathname.startsWith('/v/') || parsed.pathname.startsWith('/e/')) {
		parsed.pathname = `/embed/${parsed.pathname.slice(3)}`
		parsed.search = ''
		return parsed.href
	}
	return null
}
```

Apparently, a url like `https://www.youtube.com.attacker.com/watch?v=abc` will be converted into `https://www.youtube.com.attacker.com/embed/abc`, so this means we can embed any external website in the iframe.

But there is actually more than that as it doesn't check nor overwrite the `protocol` part of the url, so we can try to play with `file://`. For example, `file://www.youtube.com.attacker.com/watch?v=../etc/passwd` would become `file://www.youtube.com.attacker.com/etc/passwd`, but that mandatory hostname part is blocking us from loading local files.

It turns out Chromium would accept any hostname ends with `.localhost` for `file://` urls, so `file://www.youtube.com.localhost/etc/passwd` works.

Suppose we want to include a html at `/tmp/harmony/exp.html`, we can use `file://www.youtube.com.localhost/watch?v=../tmp/harmony/exp.html`, which will be converted into `file://www.youtube.com.localhost/tmp/harmony/exp.html`.

But there actually trying to do so doesn't really work as DOMPurify `file://` isn't allowed by DOMPurify by default. Fortunately, the application's main page is also loaded from `file://`, so `//www.youtube.com.localhost/watch?v=../tmp/harmony/exp.html` would automatically become `file://www.youtube.com.localhost/tmp/harmony/exp.html` when you read it from `href` **property**. This works because DOMPurify only [sanitize using **attributes**](https://github.com/cure53/DOMPurify/blob/926a8cd1755e14bd1523c4e034e4c01f361e9218/src/purify.js#L1227), not properties.

### Uploaded filename mismatch

The [file uploading progress](./dist/client/src/components/Chat.vue#L46-L64) can be described as:

1. Client send `uploadFile` event to the server along with data and filename.
2. Server returns file id to the client.
3. Client send `sendMessage` event with type `file`, file id and a *filename*.

Once the other client receives the `sendMessage` event, it will check if the filename extension is an image, and try to [download the file from the server](./dist/client/src/components/FileMessage.vue#L18). The [`download-to-temp` handler](./dist/client/electron/main.ts#L98-L113) in the main process fetch the file from server and use the filename in `Content-Disposition` header as the filename to save.

The problem is that two filenames can be different, so it allows you to save file using arbitrary filenames.

> There is a `path.join` path traversal there too, but it is totally a mistake. I hope that didn't mislead you :(

### `file://` is same-origin in Electron

Once you use `file://` to embed custom html to iframe, you will see that it is possible to access top frame objects freely using `top.*`. This is really unexpected as `file://` is not same-origin in browsers (They are opaque origin).

Anyway, this means you can access `top.api` to touch apis written in [preload.ts](./dist/client/electron/preload.ts).

> The origin of `file://` appear to be [implementation-defined](https://stackoverflow.com/questions/48313084/what-is-the-same-origin-policy-for-file-uris), so it is not really an Electron bug. But it is still an interesting behavior as it differs from Chromium.

### Boolean-only prototype pollution

In [config.ts](./dist/client/electron/config.ts), `setChannels` have a prototype pollution if `username` is `__proto__`, but due to the schema verification you can only set it to `true` or `false`.

What can we pollute with this? In my solution, all you need is to make `Object.prototype.sandbox` to be `false` so that new prompt runs without sandbox.

### `setHTML` still allows `meta` tag

In [prompt.html](./dist/client/public/prompt.html), it will use `setHTML` to display your prompt message, and it allows `meta` tag by default so you can do meta redirect to external websites in that prompt window.

> The same trick is used in [Canvas](../Canvas) too.

Here, we can still access `window.api` in preload script too, except we are not restricted by [Electron sandbox](https://www.electronjs.org/docs/latest/tutorial/sandbox).

### RCE using Client-side prototype pollution

Now, you can execute arbitrary JavaScript in a window with `contextIsolation` and `sandbox` disabled, can you escape?

There was a research called [ElectroVolt](https://i.blackhat.com/USA-22/Thursday/US-22-Purani-ElectroVolt-Pwning-Popular-Desktop-Apps.pdf), which shows various ways to exploit an Electron application. In page 25, it shows that you can use *prototype pollution* to leak Electron's internal modules.

Why does this happens? It is because `contextIsolation` refers to whether preload script (and Electron's internal) is isolated from the code running on the website. When `contextIsolation` is disabled, things like `Object.prototype`, `Function.prototype` and many things are shared, so **it is possible to change the behavior of internal modules by modifying builtin functions**.

In this challenge, we use the fact that `electron.ipcRenderer` is actually a getter that will lazy load the module on demand. Relevant code: [lib/common/define-properties.ts](https://github.com/electron/electron/blob/v26.1.0/lib/common/define-properties.ts) and [lib/renderer/api/module-list.ts](https://github.com/electron/electron/blob/v26.1.0/lib/renderer/api/module-list.ts) (All these can be found by putting a breakpoint and trace into Electron's internal)

In the second file, we know it will eventually calls `require("./lib/renderer/api/ipc-renderer.ts")`, and the `require` function is actully a polyfill provided by Webpack. It looks like this:

```javascript
function __webpack_require__(r) {
	var n = t[r];
	if (void 0 !== n)
		return n.exports;
	var i = t[r] = {
		exports: {}
	};
	return e[r](i, i.exports, __webpack_require__),
	i.exports
}
```

It is obvious that `t` stores cached modules. When `require("./lib/renderer/api/ipc-renderer.ts")` is called the first time, `n` wouldn't exist so it will try to create an entry for it and call `e[r]` to initialize it.

If we try to hook the `t[r] = {}` assignment before it is called, we will get `t` from `this` of the setter function, which means we can get `module` module. This means we can basically require anything we want, so we have a full RCE here.

```javascript
Object.defineProperty(Object.prototype, './lib/renderer/api/ipc-renderer.ts', {
    set(v) {
        console.log('set', v)
        this.module.exports._load('child_process').execSync('id')
    }
})
```

My full solver is [here](./exp/index.js).

### Unintended - RCE using `webview` preload

@drbrix from justCatTheFish solved this challenge in a mostly same way, except for the last step

When using prototype pollution, he pollutes `Object.prototype.sandbox` to `false` and `Object.prototype.webview` to `true`. This means the new prompt window will webview tag available, so you can get an easy RCE by:

```html
<webview src="http://example.com/" preload="file:///tmp/harmony/whatever.js"></webview>
```

Then in `whatever.js`, you can `require` anything you want.

## If you having problem running the challenge locally

Sorry, I made a similar mistake described in [**Instancer Fix**](../Login%20System/README.md) section of Login System. You need to move `WORKDIR` before using `yarn` to install dependencies.

Another way to fix it is to go into `server` and `spawner/www` and run `yarn` manually before running `docker compose up -d`.
