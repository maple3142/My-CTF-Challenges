# Flag Checker

* Category: Reverse
* Score: 500/500
* Solves: 3/286

## Description

Just a flag checker and nothing more.

## Overview

很單純的一個 Linux x64 flag checker，從 stdin 讀 flag 然後輸出 `Good` 或是 `Bad` 而已。直接跑可能會因為 glibc 版本太舊而跑不動，建議在 ubuntu 22.04 之類的系統上跑才能跑了動。

## Solution

### ELF

直接拿 IDA 打開會看到 `main` 很單純的讀了 flag 進來到 bss，然後呼叫一個像是 check 的函數之後輸出正不正確而已。但是試著在 Ubuntu 22.04 的 Docker 直接跑它會出現 `Bad OS` 的訊息。去 `init_array` 找看看會發現一個函數裡面會呼叫 `stat` 然後看情況輸出 `Bad OS`，而 `stat` 的目標檔名可以看出是被混淆的，但是 gdb 動態追就能看出它是在檢查有沒有 `/usr/bin/python3` 的存在。

而 check 函數中可以知道它只檢查了 flag prefix 是不是 `AIS3{` 和是不是每個字元都大於 20 以外就沒其他檢查了:

```c++
__int64 sub_120E()
{
  char v1; // [rsp+0h] [rbp-10h] BYREF
  char *v2; // [rsp+8h] [rbp-8h]

  v2 = &v1;
  if ( strncmp("AIS3{", s2, 5uLL) )
    return 0LL;
  if ( !(unsigned __int8)sub_11DB(s2) )
    return 0LL;
  *((_QWORD *)v2 + 3) = off_40D0;
  *((_QWORD *)v2 + 4) = 59LL;
  *((__int64 (__fastcall **)())v2 + 5) = off_40D8[0];
  *((_QWORD *)v2 + 6) = qword_41A0;
  *((__int64 (__fastcall **)())v2 + 7) = off_40E0[0];
  *((_QWORD *)v2 + 8) = &qword_40A0;
  *((_QWORD *)v2 + 9) = off_40E8;
  *((_QWORD *)v2 + 10) = environ;
  *((_QWORD *)v2 + 11) = off_40C8;
  return 1LL;
}
```

雖然看起來只要符合上面的條件它就會 return 1 然後輸出 `Good`，但實際測試根本不是這樣，很明線問題出在那些奇怪的 assignments。算一下 `v2` 的值和 stack 的位置其實就能看出 `v2+3` 指的位置是 return address，所以它算是在寫 ROP chain。也能透過觀察出 `40C8`, `40D0`, `40D8`, `40E0` 和 `40E8` 分別是 `syscall`, `pop rax; ret`, `pop rdi; ret`, `pop rsi; ret`, `pop rdx; ret` 的 gadget，因此那些實際上是在做 execve 的 syscall。

動態追就能知道 `41A0` 的是 `/usr/bin/python3`，而 `40A0` 是 argv:

```
argv[0]: python3
argv[1]: -c
argv[2]: __import__('pickle').loads(bytes.fromhex('800495e6...
argv[3]: test}
```

`test}` 的部分實際上是 `flag+5`，也就是 flag 去掉 prefix 的部分。所以這邊可以知道這個 ELF 只是為了把 flag 後半放到一個 pickle 程式中去做 checking 而已。

還有上面這些其實有個很簡單的方法可以跳過，就是直接用神奇的 `strace` 就能抓出它 execve 的參數。

### Pickle

上面的 `argv[2]` 完整展開是這樣:

```python
__import__('pickle').loads(bytes.fromhex('800495e601000000000000288c086275696c74696e738c0a5f5f696d706f72745f5f938c037379738552948c086275696c74696e738c076765746174747293948c086f70657261746f728c076765746974656d9394680168008c046172677686524b0186528c06656e636f6465865229529468039468018c086275696c74696e738c03696e74938c0a66726f6d5f6279746573865268048c03626967865294680594493534323733323331363937373935303531303439373237303139303530313032313739313735373339353536383133393132363733393937373438373031393138343534313033333936363639313933383934303932363634393133383431313338313139383432363836363237383939313437330a946807948c086f70657261746f728c026571938c086275696c74696e738c03706f779368064b1068088752493230303638333736343330313433373830333031303638313334373535343931313034343731333535323137313232383839303430323339313634333032373239393337353335323338303639343434303036353539353932353533383237303531373935343036363436393934313937353735370a8652946809946802288c034261648c04476f6f646c680a865294680b948c086275696c74696e738c057072696e7493680c8552314e2e'))
```

使用 `pickletools.dis` 可以讓它 dump 出 disassembly:

```
    0: \x80 PROTO      4
    2: \x95 FRAME      486
   11: (    MARK
   12: \x8c     SHORT_BINUNICODE 'builtins'
   22: \x8c     SHORT_BINUNICODE '__import__'
   34: \x93     STACK_GLOBAL
   35: \x8c     SHORT_BINUNICODE 'sys'
   40: \x85     TUPLE1
   41: R        REDUCE
   42: \x94     MEMOIZE    (as 0)
   43: \x8c     SHORT_BINUNICODE 'builtins'
   53: \x8c     SHORT_BINUNICODE 'getattr'
   62: \x93     STACK_GLOBAL
   63: \x94     MEMOIZE    (as 1)
   64: \x8c     SHORT_BINUNICODE 'operator'
   74: \x8c     SHORT_BINUNICODE 'getitem'
   83: \x93     STACK_GLOBAL
   84: \x94     MEMOIZE    (as 2)
   85: h        BINGET     1
   87: h        BINGET     0
   89: \x8c     SHORT_BINUNICODE 'argv'
   95: \x86     TUPLE2
   96: R        REDUCE
   97: K        BININT1    1
   99: \x86     TUPLE2
  100: R        REDUCE
  101: \x8c     SHORT_BINUNICODE 'encode'
  109: \x86     TUPLE2
  110: R        REDUCE
  111: )        EMPTY_TUPLE
  112: R        REDUCE
  113: \x94     MEMOIZE    (as 3)
  114: h        BINGET     3
  116: \x94     MEMOIZE    (as 4)
  117: h        BINGET     1
  119: \x8c     SHORT_BINUNICODE 'builtins'
  129: \x8c     SHORT_BINUNICODE 'int'
  134: \x93     STACK_GLOBAL
  135: \x8c     SHORT_BINUNICODE 'from_bytes'
  147: \x86     TUPLE2
  148: R        REDUCE
  149: h        BINGET     4
  151: \x8c     SHORT_BINUNICODE 'big'
  156: \x86     TUPLE2
  157: R        REDUCE
  158: \x94     MEMOIZE    (as 5)
  159: h        BINGET     5
  161: \x94     MEMOIZE    (as 6)
  162: I        INT        542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473
  281: \x94     MEMOIZE    (as 7)
  282: h        BINGET     7
  284: \x94     MEMOIZE    (as 8)
  285: \x8c     SHORT_BINUNICODE 'operator'
  295: \x8c     SHORT_BINUNICODE 'eq'
  299: \x93     STACK_GLOBAL
  300: \x8c     SHORT_BINUNICODE 'builtins'
  310: \x8c     SHORT_BINUNICODE 'pow'
  315: \x93     STACK_GLOBAL
  316: h        BINGET     6
  318: K        BININT1    16
  320: h        BINGET     8
  322: \x87     TUPLE3
  323: R        REDUCE
  324: I        INT        200683764301437803010681347554911044713552171228890402391643027299375352380694440065595925538270517954066469941975757
  443: \x86     TUPLE2
  444: R        REDUCE
  445: \x94     MEMOIZE    (as 9)
  446: h        BINGET     9
  448: \x94     MEMOIZE    (as 10)
  449: h        BINGET     2
  451: (        MARK
  452: \x8c         SHORT_BINUNICODE 'Bad'
  457: \x8c         SHORT_BINUNICODE 'Good'
  463: l            LIST       (MARK at 451)
  464: h        BINGET     10
  466: \x86     TUPLE2
  467: R        REDUCE
  468: \x94     MEMOIZE    (as 11)
  469: h        BINGET     11
  471: \x94     MEMOIZE    (as 12)
  472: \x8c     SHORT_BINUNICODE 'builtins'
  482: \x8c     SHORT_BINUNICODE 'print'
  489: \x93     STACK_GLOBAL
  490: h        BINGET     12
  492: \x85     TUPLE1
  493: R        REDUCE
  494: 1        POP_MARK   (MARK at 11)
  495: N    NONE
  496: .    STOP
highest protocol among opcodes = 4
```

這部分我的預期作法就真的是直接讀 disassembly，只要了解基本的幾個 `GLOBAL`, `REDUCE`, `MEMORIZE`, `BINGET` 等等的功能之後花點時間就能一步一步把它寫成這樣的 Python:

```python
memo[0] = __import__('sys')
memo[1] = getattr
memo[2] = operator.getitem
memo[3] = memo[1](memo[2](memo[1](memo[0], 'argv'), 1), 'encode')()
memo[4] = memo[3]
memo[5] = memo[1](int, 'from_bytes')(memo[4], 'big')
memo[6] = memo[5]
memo[7] = 542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473
memo[8] = memo[7]
memo[9] = operator.eq(pow(memo[6], 16, memo[8]), 200683764301437803010681347554911044713552171228890402391643027299375352380694440065595925538270517954066469941975757)
memo[10] = memo[9]
memo[11] = memo[2](['Bad', 'Good'], memo[10])
memo[12] = memo[11]
print(memo[12])
```

簡化一下:

```python
import sys

flag = sys.argv[1].encode()
inp = int.from_bytes(flag, "big")
p = 542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473
eq = (
    pow(inp, 65537, p)
    == 451736263303355935449028567064392382249020023967373174925770068593206982683303653948838172763093279548888815048027759
)
msg = ["Bad", "Good"][eq]
print(msg)
```

> 這個階段說不定也可以透過自己 patch [Fickling](https://github.com/trailofbits/fickling)，幫它加上 `LIST` 之類的功能也就能 decompile 了。

### Math

可知它把 `sys.argv[1]` (也就是 `flag+5`) 以 big endian 轉換成數字 $m$，然後檢查 $m^{65537} \bmod{p} \stackrel{?}{=} c$。所以要逆回去的話就相當於在 $\bmod{p}$ 的情況下開 $65537$ 次方根。知道 RSA 的人應該會覺得這個很熟悉，因為它就是 RSA。

檢查一下可知 $p$ 是個質數，所以這個情況下的 RSA 是非常容易的。先算 $d \equiv 65537^{-1} \pmod{p-1}$，然後 $m \equiv c^d \pmod{p}$ 就能將需要的 $m$ 找回來了:

```python
from Crypto.Util.number import long_to_bytes

c = 451736263303355935449028567064392382249020023967373174925770068593206982683303653948838172763093279548888815048027759
p = 542732316977950510497270190501021791757395568139126739977487019184541033966691938940926649138411381198426866278991473
d = pow(65537, -1, p - 1)
m = pow(c, d, p)
print(long_to_bytes(m))
```

> 原本的 source code 放在 [src](./src) 資料夾中
