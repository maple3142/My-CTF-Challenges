# Media Server

* Category: Misc
* Score: 500/500
* Solves: 2/247

## Description

A simple HTTP server written in Python for serving media efficiently!

## Overview

一個基於 Python `http.server.BaseHTTPRequestHandler` 寫個 file server，有特別處理 `Range` header 來支援 HTTP range request。

## Solution

一開始可以發現 `do_media` 有機會讓你讀任意檔案:

```python
    def do_media(self):
        filepath = self.path[1:]
        if os.path.exists(filepath):
            # ...
```

例如 `self.path` 是 `/../etc/passwd` 就能讀到 `/etc/passwd`。(但 `//etc/passwd` 不行[^1])

但 `do_GET` 裡面有檢察 `self.path` 是否是 `/media` 開頭，所以 `GET /../etc/passwd` 是無效的:

```python
    def do_GET(self):
        if re.fullmatch(r"/media/[a-zA-Z0-9.]+", self.path):
            return self.do_media()
        # ...
```

不過只要進去讀 BaseHTTPRequestHandler 的 source code 的話可以發現它裡面是會自動找 `do_$HTTPMETHOD` 的函數來當作 handler 的: [source](https://github.com/python/cpython/blob/b9c807a260f63284f16e25b5e98e18191f61a05f/Lib/http/server.py#L417-L424)

所以這邊只要用 `media` 當作 HTTP method 就可以 bypass 這個檢查了。

```bash
> curl -X media --path-as-is 'http://chals1.ais3.org:25519/../etc/passwd'
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
...
```

現在可以任意讀檔了，但還是拿不到 flag，因為 flag 只能透過執行 `/readflag` 才能讀取，而在沒有 RCE 的方法之下唯一能讀 flag 的方法是靠 `do_GET` 裡面的這段 code:

```python
        elif self.path == secret_path:
            with os.popen("/readflag", "r") as f:
                self.send_response(200)
                self.send_header("Content-type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(f.read().encode())
```

而其中的 `secret_path` 是在 server 啟動時用 `secret_path = "/flag_" + os.urandom(16).hex()` 生成的隨機 path。雖然這個沒有存在任何檔案中，但它肯定是存在 Python process 的記憶體中的，所以如果有機會利用前面任意讀檔去讀任意記憶體的話就能拿到這個 `secret_path` 了。

這個在 Linux 利用 `/proc` 是真的可行的，關鍵是 `/proc/$pid/mem` [^2] 可以利用 `seek` 到指定的 address 去就能讀到 memory 的值，而 `/proc/$pid/maps` 也會告訴你一個 process 的 memory map，裡面就有很多 page 的記憶體位置了。不清楚怎麼做可以參考 [How do I read from /proc/$pid/mem under Linux?](https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux)。

所以利用 `Range` header 就能讀記體了，寫個 script 整個 process 掃過一遍就能找到目標的 `secret_path` 了。如果之前有人讀過 flag 了的話 flag 也有可能還殘留在記憶體中。

另一個不用全部掃的方法是在 local 啟動 python server，然後用 `hex(id(secret_id))` 看看是在 `/proc/self/maps` 的哪個區塊，那麼 remote 也會把 path 放在那個區塊，那就能用一個 request 直接讀出 path 了。

這個題目其實是從 [LINE CTF 2022 - online library](https://blog.maple3142.net/2022/03/27/line-ctf-2022-writeups/#online-library) 修改而來的。

[^1]: 這是因為 CPython 會自動把多個 `/` 轉成單個 `/`: [source](https://github.com/python/cpython/blob/b9c807a260f63284f16e25b5e98e18191f61a05f/Lib/http/server.py#L341-L342)
[^2]: 這邊 pid 可以是 `self`
