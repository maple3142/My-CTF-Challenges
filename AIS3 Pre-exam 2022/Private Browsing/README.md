# Private Browsing

* Category: Web
* Score: 500/500
* Solves: 4/286

## Description

I built my own browser-based private browsing service, it proxies your traffic and ensures no JavaSrcipt get executed to protect your privacy!

Execute /readflag to get flag.

> Recommended readings: https://github.com/splitline/How-to-Hack-Websites

## Overview

> PS: 此題解題時是沒辦法直接下載 source code 的

有個簡單的模擬瀏覽器的服務，會呼叫伺服器的 api 向其他 url 發送請求然後顯示在一個 iframe 之中。

## Solution

它是使用 `/api.php?action=view&url=...` 來使用伺服器來 fetch 其他網站的，所以直覺上就知道可能有 SSRF。

測試 `file:///etc/passwd` 也能成功任意讀檔，所以只要能猜中 server 網站的目錄就能讀到 source code。若有在 Debian 系的系統上面架過網頁的經驗或是 Google 一下常見的網頁目錄應能猜中檔案是放在 `/var/www/html`，所以用 `file:///var/www/html/api.php` 就能看到 `api.php` 的原始碼。不過這邊也有個不用猜目錄也能讀檔的方法: `file:///proc/self/cwd/api.php`。

讀了一下 `api.php` 可知它有使用 session 來記錄瀏覽過的歷史紀錄，而 session 處理的部分都放在 `session.php` 之中，所以一樣去讀檔看看有沒有可利用的點。

從 `session.php` 可知它使用了 redis 作為 session store，但是處理 session 的部分是使用自己的 class 來處理而非 php 本身的 redis session。關鍵的部分如下:

```php
<?php
$redis = new Redis();
$redis->connect('redis', 6379);
class SessionManager
{
    function __construct($redis, $sessid, $fallback, $encode = 'serialize', $decode = 'unserialize')
    {
        $this->redis = $redis;
        $this->sessid = $sessid;
        $this->encode = $encode;
        $this->decode = $decode;
        $this->fallback = $fallback;
        $this->val = null;
    }

    function get()
    {
        if ($this->val !== null) {
            return $this->val;
        }
        if ($this->redis->exists($this->sessid)) {
            $this->val = ($this->decode)($this->redis->get($this->sessid));
        } else {
            $this->val = ($this->fallback)();
        }
        return $this->val;
    }

    function __destruct()
    {
        global $redis;
        if ($this->val !== null) {
            $redis->set($this->sessid, ($this->encode)($this->val));
        }
    }

    function __call($name, $arguments)
    {
        return $this->get()->{$name}(...$arguments);
    }

    static function load_from_cookie($name, $fallback)
    {
        global $redis;
        if (isset($_COOKIE[$name])) {
            $sessid = $_COOKIE[$name];
        } else {
            $sessid = bin2hex(random_bytes(10));
            setcookie($name, $sessid);
        }
        return new SessionManager($redis, $sessid, $fallback);
    }
}

// in api.php:
$session = SessionManager::load_from_cookie('sess_id', ['BrowsingSession', 'new']);
```

同時有 SSRF 和 redis 也只會讓人想到透過 redis RCE，但是一般情況下是沒辦法直接透過 redis 本身去執行指令的(需要額外的 CVE)。所以常見的 redis ssrf 通常是想辦法攻擊 session 或是寫 webshell 等等。

測試一下可知 `CONFIG` 等等的指令都被封鎖了，所以沒辦法寫 webshell，因此目前剩下的方法就是看看能不能控制 session。從 `session.php` 可知它會從 redis 中以 cookie `sess_id` 的值去讀東西，然後透過 php 的 `unserialize` 去處理。這就代表透過 SSRF 去寫 redis 就能控制 `unserialize` 的輸入，看看能不能找到某個 gadget chain 去拿 RCE。

不過這邊可以知道它都沒使用什麼 class loader，所以能用的 class 很少，最有可能的就只有 `SessionManager` 而已。在 `__destruct` 的裡面有 `($this->encode)($this->val)`，所以當 `$this->encode === 'system'` 時只要控制 `$this->val` 就能執行指令了，這樣就有個非常直接的 gadget 能用。

剩下就是寫點 php 生成 payload，然後用 gopher ssrf redis 寫 payload 到指定的 `sess_id` 去，然後另外再發個 request 讓它觸發 `__destruct` 就能 RCE。solver 在 [exp/exp.py](exp/exp.py)。
