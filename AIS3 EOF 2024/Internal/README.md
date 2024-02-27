# Internal

* Category: Web
* Score: 176/500

## Description

The flag is for internal use only!

## Overview

目標 bypass nginx 的限制去讀到 `/flag`。

## Solution

第一件事是 python `re.match` 只 match string 的開頭，所以只要前面 match 完之後後面隨便加東西都會過，而 url 又會被拿去當作 header，由於 `BaseHTTPRequestHandler` 沒有做額外保護所以是可以 CRLF Injection 的。

nginx 會接受一個特殊 header `X-Accel-Redirect`，它會在 nginx 內部做 redirect (對於外部來說看不出來) 也可以存取 `internal` 的資源，所以直接讓 nginx 用 `X-Accel-Redirect: /flag` 就行了。

```bash
curl -v 'http://.../' -G --data-urlencode $'redir=http://asd\r\nX-Accel-Redirect:/flag'
```

不過後來才發現原來約 10 年前就有和這個幾乎相同的題目了...: [writeup](https://blog.orange.tw/2014/02/olympic-ctf-2014-curling-200-write-up.html)。
