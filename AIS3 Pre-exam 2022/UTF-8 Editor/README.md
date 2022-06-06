# UTF-8 Editor

* Category: Pwn

Shell

* Score: 400/400
* Solves: 2/286

Crash

* Score: 100/100
* Solves: 9/286
* Score(MFCTF): 250/250
* Solves(MFCTF): 1/124

## Description

A simple UTF-8 editor written in C++, nothing can go wrong right?

## Overview

這題是個 C++ Linux x64 的程式。程式一開始可以輸入一個 UTF-8 的字串，然後它會 decode 後以 codepoint 為單位儲存字串，支援 print 單獨的 codepoint 或是編輯 codepoint 等等的操作。

## Solution

### Crash

首先要先找到題目的 bug 在哪才能讓它 crash，但是大致掃過去是不容易看出哪裡有問題的，向是輸入 index 的地方都有經過 bound checking 等等。

```c++
class utf8_string {
   public:
	std::vector<uint32_t> data;  // UTF-8 codepoints
	friend std::istream &operator>>(std::istream &is, utf8_string &obj);
	friend std::ostream &operator<<(std::ostream &os, utf8_string &obj);

   public:
	size_t length() { return data.size() - 1; }
	uint32_t &operator[](int i) { return data[i]; }
};
```

這題的關鍵在於 `length()` 的實作，因為 `data.size()` 是 unsigned int，`0-1` 後會直接 underflow 變很大的數字，而 `main` 中的 `idx` 是 signed int 所以能導致 bound checking 直接失效得到 OOB read/write。

雖然 `operator>>` 函數一般會在讀完字串後 `push_back(0)`，但只要 parse utf8 失敗就能讓它直接 return，導致 `data.size() == 0` 然後就有前面的 OOB。

一個最簡單就能讓它 crash 的 payload 如下:

```bash
echo -n '\xff\n3\n0\n' | nc chals1.ais3.org 6003
```

> 如果使用了中文 Windows，然後在 powershell 或是 cmd 環境底下使用 `nc` 連線時直接輸入中文有可能可以直接拿到 Crash Flag，因為它大概是直接傳 Big5...

### Shell

下一步是要怎麼利用 `std::vector` 的 OOB 去拿 shell，首先得知道 `std::vector` 在 OOB 的時候到底是存取了什麼東西，這部分可以寫個簡單的 C++ 來驗證:

```c++
#include <vector>
#include <stdio.h>
using namespace std;

int main(){
    vector<int> v;
    printf("%u %p %p\n", v.capacity(),&v[0], v.data());
    vector<int> v2({1});
    printf("%u %p %p\n", v2.capacity(), &v2[0], v2.data());
    return 0;
}
```

用 `g++` 編譯後執行的輸出是:

```
0 (nil) (nil)
1 0x5578b8a7c2c0 0x5578b8a7c2c0
```

所以可知當它還沒有 allocate 東西時的 base address 是 `0`。再來 `checksec` 檢查一下:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

所以一個明顯的打法是透過修改 GOT 拿 shell。而這題的 GOT table 在 IDA 中是長這樣:

```
.got.plt:0000000000406000 ; ===========================================================================
.got.plt:0000000000406000
.got.plt:0000000000406000 ; Segment type: Pure data
.got.plt:0000000000406000 ; Segment permissions: Read/Write
.got.plt:0000000000406000 _got_plt        segment qword public 'DATA' use64
.got.plt:0000000000406000                 assume cs:_got_plt
.got.plt:0000000000406000                 ;org 406000h
.got.plt:0000000000406000 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000406008 qword_406008    dq 0                    ; DATA XREF: sub_401020↑r
.got.plt:0000000000406010 qword_406010    dq 0                    ; DATA XREF: sub_401020+6↑r
.got.plt:0000000000406018 off_406018      dq offset setvbuf       ; DATA XREF: _setvbuf↑r
.got.plt:0000000000406020 off_406020      dq offset _ZNSirsERj    ; DATA XREF: std::istream::operator>>(uint &)↑r
.got.plt:0000000000406020                                         ; std::istream::operator>>(uint &)
.got.plt:0000000000406028 off_406028      dq offset _ZSt17__throw_bad_allocv
.got.plt:0000000000406028                                         ; DATA XREF: std::__throw_bad_alloc(void)↑r
.got.plt:0000000000406028                                         ; std::__throw_bad_alloc(void)
.got.plt:0000000000406030 off_406030      dq offset __cxa_begin_catch
.got.plt:0000000000406030                                         ; DATA XREF: ___cxa_begin_catch↑r
.got.plt:0000000000406038 off_406038      dq offset _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv
.got.plt:0000000000406038                                         ; DATA XREF: std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(void)↑r
.got.plt:0000000000406038                                         ; std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(void)
.got.plt:0000000000406040 off_406040      dq offset _ZSt20__throw_length_errorPKc
.got.plt:0000000000406040                                         ; DATA XREF: std::__throw_length_error(char const*)↑r
.got.plt:0000000000406040                                         ; std::__throw_length_error(char const*)
.got.plt:0000000000406048 off_406048      dq offset _ZNSirsERi    ; DATA XREF: std::istream::operator>>(int &)↑r
.got.plt:0000000000406048                                         ; std::istream::operator>>(int &)
.got.plt:0000000000406050 off_406050      dq offset _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev
.got.plt:0000000000406050                                         ; DATA XREF: std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string()↑r
.got.plt:0000000000406050                                         ; std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string()
.got.plt:0000000000406058 off_406058      dq offset __cxa_atexit  ; DATA XREF: ___cxa_atexit↑r
.got.plt:0000000000406060 off_406060      dq offset _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
.got.plt:0000000000406060                                         ; DATA XREF: std::operator<<<std::char_traits<char>>(std::ostream &,char const*)↑r
.got.plt:0000000000406060                                         ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
.got.plt:0000000000406068 off_406068      dq offset _Znwm         ; DATA XREF: operator new(ulong)↑r
.got.plt:0000000000406068                                         ; operator new(ulong)
.got.plt:0000000000406070 off_406070      dq offset _ZdlPvm       ; DATA XREF: operator delete(void *,ulong)↑r
.got.plt:0000000000406070                                         ; operator delete(void *,ulong)
.got.plt:0000000000406078 off_406078      dq offset _ZNSolsEPFRSoS_E
.got.plt:0000000000406078                                         ; DATA XREF: std::ostream::operator<<(std::ostream & (*)(std::ostream &))↑r
.got.plt:0000000000406078                                         ; std::ostream::operator<<(std::ostream & (*)(std::ostream &))
.got.plt:0000000000406080 off_406080      dq offset _ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE
.got.plt:0000000000406080                                         ; DATA XREF: std::operator>><char>(std::istream &,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>> &)↑r
.got.plt:0000000000406080                                         ; std::operator>><char>(std::istream &,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>> &)
.got.plt:0000000000406088 off_406088      dq offset _ZNSolsEj     ; DATA XREF: std::ostream::operator<<(uint)↑r
.got.plt:0000000000406088                                         ; std::ostream::operator<<(uint)
.got.plt:0000000000406090 off_406090      dq offset _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev
.got.plt:0000000000406090                                         ; DATA XREF: std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(void)↑r
.got.plt:0000000000406090                                         ; std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(void)
.got.plt:0000000000406098 off_406098      dq offset __cxa_rethrow ; DATA XREF: ___cxa_rethrow↑r
.got.plt:00000000004060A0 off_4060A0      dq offset _ZNSt8ios_base4InitC1Ev
.got.plt:00000000004060A0                                         ; DATA XREF: std::ios_base::Init::Init(void)↑r
.got.plt:00000000004060A0                                         ; std::ios_base::Init::Init(void)
.got.plt:00000000004060A8 off_4060A8      dq offset memmove       ; DATA XREF: _memmove↑r
.got.plt:00000000004060B0 off_4060B0      dq offset __cxa_end_catch
.got.plt:00000000004060B0                                         ; DATA XREF: ___cxa_end_catch↑r
.got.plt:00000000004060B8 off_4060B8      dq offset _Unwind_Resume
.got.plt:00000000004060B8                                         ; DATA XREF: __Unwind_Resume↑r
.got.plt:00000000004060B8 _got_plt        ends
.got.plt:00000000004060B8
```

首先可以很容易的透過 OOB read 從 `setvbuf` 上拿到 libc address，因為是 32 bits 所以要讀兩次才行。一個直接的做法是寫 one gadget，但我在這題的 docker 環境中找不到一個能夠正常使用的 one gadget，所以只好放棄這條路。

> PS: 不過 Kia 有找到其他方法弄 one gadget，看來我還是太嫩了==

我想的做法是利用 `main` 最一開始執行的函數是 `setvbuf(stdin, 0LL, 2, 0LL);`，因為 `stdin` 是個在 bss 的 pointer，指向 libc 中的 stdin FILE，所以只要把那個 points 改寫為指向 libc 中的 `/bin/sh` 字串，同時把 `setvbuf` 變成 `system` 之後下次回到 `main` 就能拿 shell 了。

下個步驟是要找方法把程式弄回 `main`，但是因為此時的 GOT 中很多的函數都已經不再是指向 plt 了，在只能寫 32 bits 的情況下又沒辦法一次把 libc 或是 libstdc++ 的函數變回 `main`，只寫一半的 pointer 又會直接 segfault。

解法是仔細觀察原本的程式可知 `std::cout << str[idx] << std::endl;` 只出現在選項 `3`，它呼叫的是 `cout << uint32_t` (`_ZNSolsEj`) 也只在這邊出現而已。所以以它作為改寫目標就能在兩次 write 之間確保寫一半的 pointer 不會被 call 到。

把 `_ZNSolsEj` 寫回 main 之後選 `3` 之後就能拿 shell 了。

整個詳細的流程可以參考 [solve.py](solve.py)。
