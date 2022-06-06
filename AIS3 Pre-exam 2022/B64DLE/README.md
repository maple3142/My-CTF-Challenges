# B64DLE

* Category: Misc
* Score: 500/500
* Solves: 0/286

## Description

Wordle is too boring? Try this base64 wordle variant!

## Overview

這題是個簡單的 Base64 版本的 Wordle 遊戲，要猜的單字是 `base64(five_letter_word)`，所以輸入都要是正常的 Base64，然後 server 端會用一般 Wordle 比較的方法告訴你一個字元是不是正確/位置錯誤/不存在。

不過並不是解掉遊戲就能勝利，目標是要想辦法透過它的 login token 從環境變數中拿到 `FLAG`。Token 本身是 `AESCTR(pickle(data))` 的方法包裝的。

## Solution

### Win a game

首先這題很明顯是要透過 login token 去做某些操作，但是要儲存 token 的話需要至少贏一場才行，所以得透過附加的 words list 寫個 solver 才行。

solver 邏輯也很簡單，先拿 words list 當作初始的 candidates，然後從其中隨機抓單字的 base64 傳送過去，之後透過回傳的結果把 candidates 給篩選一遍，反覆做下去就有一定機率能勝利。

主要參考 [solve.py](solve.py) 的 `win_a_round` 邏輯。

### AES-CTR

贏了之後可以拿到 login token，因為是 `AESCTR(pickle(data))` 加密的，在知道 `pickle(data)` 的情況下可以很容易的控制解密出來的資料，也就是能控制任意的 pickle 進到 `restricted_loads`。

### Pickle

```python
class Player:
    def __init__(self, name, wins=0, words=[]):
        self.name = name
        self.wins = wins
        self.words = words
        self.profile_tmpl = "=== Player {user.name} ===\nWins: {user.wins}\nGuessed words: {user.words}\n"

    def __repr__(self):
        return self.profile_tmpl.format(user=self)

    def __reduce__(self):
        return (
            Player,
            (
                self.name,
                self.wins,
                self.words,
            ),
        )


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == __name__ and name == "Player":
            return Player
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))

def restricted_loads(s):
    return RestrictedUnpickler(io.BytesIO(s)).load()
```

然而 `restricted_loads` 限制非常的嚴格，只允許將 `__main__.Player` 給載入進來，所以這就我所知是沒有 RCE 的方法的。不過可以看到 `Player.__repr__` 裡面使用了 `str.format`，如果 `profile_tmpl` 是可控的話有 leak 出其他資料的機會: [Python format string vulnerabilities](https://podalirius.net/en/articles/python-format-string-vulnerabilities/)。

從 pickle.dumps 出來的 `Player` 物件可知它是使用 `REDUCE` 把 `Player` 當作 constructor 呼叫的，沒有辦法設置 `profile_tmpl` 的值。繞過方法就是使用 pickle 的 `BUILD` 功能，它能夠讓你直接設定 `__dict__` 的內容，所以就能繞過 constructor 的限制控制 `profile_tmpl` 了。這邊要生成 payload 的話可以不用自己弄，只需要把 `Player.__reduce__` 刪除之後它自己就會改用 `BUILD` 來處理了。

### Format string

最後是要找方法利用 format string 拿環境變數，首先可以用 `{user.__init__.__globals__}` 拿到當前 `__main__` 的全域變數。然而 `from os import urandom` 這行導致 `os` 不存在於 `__globals__` 裡面，沒辦法直接拿 `os.environ`，只好找其他做法。

一個簡單的做法是利用 Python 內建的很多 module 都會 import 其他的 module 進來，例如 `pickle` 裡面就有 `sys` 可以讓人使用: `{user.__init__.__globals__[pickle].sys}`。

有 `sys` 之後就能用 `sys.modules['os']` 拿到已經 import 過的 `os`，然後從上面拿到 `os.environ['FLAG']` 即可解掉這題: `{user.__init__.__globals__[pickle].sys.modules[os].environ[FLAG]}`。

> 這個 payload 絕對不是唯一的方法，有興趣也可以試試看怎麼透過其他不同的路徑去拿 `environ`

完整作法詳見 [solve.py](solve.py)。
