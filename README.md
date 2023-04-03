# My CTF Challenges

This is some challenges I created for CTF competitions.

## TSJ CTF 2022

> It is recommended to read Crypto writeups [here](https://blog.maple3142.net/2022/02/28/tsjctf-2021-writeups/), because it supports math rendering.
> 2022/05/22: GitHub supports MathJax rendering on GitHub now, but it still have some compatibility issues, so you might still want to use the url above when having issues.

| Name                                                                | Category    | Tags                                      | Difficulty |
| ------------------------------------------------------------------- | ----------- | ----------------------------------------- | ---------- |
| [Futago](<TSJ CTF 2022/Futago>)                                     | Crypto, CSC | RSA                                       | ★          |
| [RNG++](<TSJ CTF 2022/RNG++>)                                       | Crypto      | LCG                                       | ★★         |
| [babyRSA](<TSJ CTF 2022/babyRSA>)                                   | Crypto      | RSA, ECC                                  | ★★         |
| [Top Secret](<TSJ CTF 2022/Top Secret>)                             | Crypto      | GF, dlog                                  | ★★☆        |
| [Cipher Switching Service](<TSJ CTF 2022/Cipher Switching Service>) | Crypto      | RSA, ElGamal                              | ★★☆        |
| [Signature](<TSJ CTF 2022/Signature>)                               | Crypto      | ECDSA, LLL, AES-CTR                       | ★★★        |
| [RNG+++](<TSJ CTF 2022/RNG+++>)                                     | Crypto      | LCG, LLL                                  | ★★★☆       |
| [Nim Notes](<TSJ CTF 2022/Nim Notes>)                               | Web         | Script Gadgets, CSRF, CRLF Injection, CSP | ★★★☆       |
| [Genie](<TSJ CTF 2022/Genie>) [1]                                   | Web, Crypto | Path traversal, AES-CBC, Deserialization  | ★★★☆       |
| [Just a pyjail](<TSJ CTF 2022/Just a pyjail>)                       | Misc        | Pyjail                                    | ★★★        |

[1]: This challenge is made by both [@splitline](https://github.com/splitline/) and me.

## HITCON CTF 2022

| Name                                           | Category    | Tags                                           | Difficulty |
| ---------------------------------------------- | ----------- | ---------------------------------------------- | ---------- |
| [BabySSS](<HITCON CTF 2022/BabySSS>)           | Crypto      | SSS, CRT                                       | ★☆         |
| [Superprime](<HITCON CTF 2022/Superprime>)     | Crypto      | Binary Search, Prune and Search                | ★★☆        |
| [Chimera](<HITCON CTF 2022/Chimera>)           | Crypto      | ECM, LLL/Coppersmith, ECDLP, Hidden Subset Sum | ★★★★       |
| [LemMinX](<HITCON CTF 2022/LemMinX>)           | Misc        | LSP, XXE                                       | ★★★        |
| [Secure Paste](<HITCON CTF 2022/Secure Paste>) | Web, Crypto | JSONP, Cipher Suite Confusion, DOMPurify, CSP  | ★★★★       |

## ImaginaryCTF

| Name                                                              | Category | Tags                                       | Difficulty |
| ----------------------------------------------------------------- | -------- | ------------------------------------------ | ---------- |
| [Really Simple Algorithm](<ImaginaryCTF/Really Simple Algorithm>) | Crypto   | RSA, Continued Fractions                   | ★★         |
| [Minimal](<ImaginaryCTF/Minimal>)                                 | Pwn      | Stack pivoting, read(2) return value, SROP | ★★         |

These two challenges are created before I became a board of ImaginaryCTF.

### Round 26

| Name                                                            | Category | Tags                  | Difficulty |
| --------------------------------------------------------------- | -------- | --------------------- | ---------- |
| [Box](<ImaginaryCTF/Round 26/box>)                              | Crypto   | Affine function       | ☆          |
| [pqqp](<ImaginaryCTF/Round 26/pqqp>)                            | Crypto   | RSA, Number Theory    | ★          |
| [First RSA](<ImaginaryCTF/Round 26/first_rsa>)                  | Crypto   | RSA                   | ★☆         |
| [No modulus](<ImaginaryCTF/Round 26/no_modulus>)                | Crypto   | RSA, LLL              | ★★★        |
| [Login Please](<ImaginaryCTF/Round 26/login_please>)            | Web      | JavaScript, Prototype | ★          |
| [Read](<ImaginaryCTF/Round 26/read>)                            | Pwn      | Shellcoding           | ★☆         |
| [Not a kernel pwn](<ImaginaryCTF/Round 26/not_a_kernel_pwn>)    | Misc     | Privilege Escalation  | ★☆         |
| [Free Shell](<ImaginaryCTF/Round 26/freeshell>)                 | Misc     | Bash                  | ★★         |
| [Here's some Rev v2](<ImaginaryCTF/Round 26/heres_some_rev_v2>) | Reverse  | Pyc                   | ☆          |
| [Here's some Rev v3](<ImaginaryCTF/Round 26/heres_some_rev_v3>) | Reverse  | LCG                   | ★          |

### Round 27

| Name                                                     | Category | Tags                       | Difficulty |
| -------------------------------------------------------- | -------- | -------------------------- | ---------- |
| [RSA-CBC](<ImaginaryCTF/Round 27/rsa-cbc>)               | Crypto   | RSA                        | ☆          |
| [RSA-CBC v2](<ImaginaryCTF/Round 27/rsa-cbc-v2>)         | Crypto   | RSA, Coppersmith           | ★☆         |
| [Mobius](<ImaginaryCTF/Round 27/mobius>)                 | Crypto   | Rational Function, LLL     | ★★☆        |
| [Hello World as a Service](<ImaginaryCTF/Round 27/haas>) | Misc     | Java, Quirks               | ★☆         |
| [Baby Shell](<ImaginaryCTF/Round 27/baby_shell>)         | Pwn      | C++, std::string_view, UAF | ★          |

### Round 28

| Name                                                   | Category | Tags         | Difficulty |
| ------------------------------------------------------ | -------- | ------------ | ---------- |
| [Substitution](<ImaginaryCTF/Round 28/Substitution>)   | Crypto   | RSA, Search  | ★☆         |
| [Unchanged](<ImaginaryCTF/Round 28/Unchanged>)         | Reverse  | pthread, LCG | ★☆         |
| [Filter Master](<ImaginaryCTF/Round 28/Filter Master>) | Web      | PHP, filter  | ★★         |
| [Half FFT](<ImaginaryCTF/Round 28/Half FFT>)           | Misc     | FFT, LLL     | ★★☆        |

### Round 29

| Name                                                                 | Category | Tags                        | Difficulty |
| -------------------------------------------------------------------- | -------- | --------------------------- | ---------- |
| [Strong Prime](<ImaginaryCTF/Round 29/Strong Prime>)                 | Crypto   | DLP, CRT                    | ★☆         |
| [Web3](<ImaginaryCTF/Round 29/Web3>)                                 | Crypto   | Ethereum, ECDLP             | ★★         |
| [Req Bin](<ImaginaryCTF/Round 29/Req Bin>)                           | Web      | Python Format String, Flask | ★☆         |
| [Generic Flag Checker](<ImaginaryCTF/Round 29/Generic Flag Checker>) | Reverse  | Signal Handler              | ★☆         |
| [xkcd 835](<ImaginaryCTF/Round 29/xkcd 835>)                         | Pwn      | UAF                         | ★★         |

### Round 30

| Name                                                   | Category | Tags              | Difficulty |
| ------------------------------------------------------ | -------- | ----------------- | ---------- |
| [PowerRSA](<ImaginaryCTF/Round 30/Power RSA>)          | Crypto   | RSA               | ★          |
| [Easy DSA: LCG](<ImaginaryCTF/Round 30/Easy DSA: LCG>) | Crypto   | ECDSA, LCG, LLL   | ★★☆        |
| [Fake Flags](<ImaginaryCTF/Round 30/Fake flags>)       | Web      | Trolling          | ☆          |
| [Echo](<ImaginaryCTF/Round 30/Echo>)                   | Web      | Request Smuggling | ★☆         |

### Round 31

| Name                                 | Category | Tags       | Difficulty |
| ------------------------------------ | -------- | ---------- | ---------- |
| [KVIN](<ImaginaryCTF/Round 31/KVIN>) | Web/Misc | JavaScript | ★★         |

### Round 32

| Name                                             | Category | Tags      | Difficulty |
| ------------------------------------------------ | -------- | --------- | ---------- |
| [Poly RSA](<ImaginaryCTF/Round 32/Poly RSA>)     | Crypto   | RSA, GCD  | ★★         |
| [Old School](<ImaginaryCTF/Round 32/Old School>) | Web      | Bash, CGI | ★☆         |

## AIS3 Pre-exam 2022

| Name                                                                | Category | Tags                                        | Difficulty |
| ------------------------------------------------------------------- | -------- | ------------------------------------------- | ---------- |
| [JeetQode](<AIS3 Pre-exam 2022/JeetQode>)                           | Misc     | PPC, JQ                                     | ★☆         |
| [B64DLE](<AIS3 Pre-exam 2022/B64DLE>)                               | Misc     | AES-CTR, Pickle, Python Format String       | ★★☆        |
| [SC](<AIS3 Pre-exam 2022/SC>)                                       | Crypto   | Classic                                     | ☆          |
| [Fast Cipher](<AIS3 Pre-exam 2022/Fast Cipher>)                     | Crypto   | Modular Arithmetic                          | ☆          |
| [shamiko](<AIS3 Pre-exam 2022/shamiko>)                             | Crypto   | SHA1 Collision, DSA                         | ★☆         |
| [Really Strange oRacle](<AIS3 Pre-exam 2022/Really Strange oRacle>) | Crypto   | GCD, Binomial Theorem                       | ★☆         |
| [pettan](<AIS3 Pre-exam 2022/pettan>)                               | Crypto   | RSA Small Message, MT19937, Related Message | ★★☆        |
| [pekobot](<AIS3 Pre-exam 2022/pekobot>)                             | Crypto   | Invalid Curve Attack                        | ★★★        |
| [Flag Checker](<AIS3 Pre-exam 2022/Flag Checker>)                   | Reverse  | ROP, Pickle, Single Prime RSA               | ★★         |
| [Private Browsing](<AIS3 Pre-exam 2022/Private Browsing>)           | Web      | SSRF, Redis, PHP Deserialization            | ★★         |
| [UTF-8 Editor](<AIS3 Pre-exam 2022/UTF-8 Editor>)                   | Pwn      | C++, std::vector, OOB, GOT overwrite        | ★★         |
| [SAAS](<AIS3 Pre-exam 2022/SAAS>)                                   | Pwn      | C++, Copy Constructor, UAF                  | ★★☆        |

## AIS3 EOF 2023 - koh-jeopardy

| Name                                                                    | Category | Tags                  | Difficulty |
| ----------------------------------------------------------------------- | -------- | --------------------- | ---------- |
| [Shamiko no fukushuu](<AIS3 EOF 2023/koh-jeopardy/shamiko_no_fukushuu>) | Crypto   | ECDSA, Hmac collision | ★          |
| [onelinecrypto](<AIS3 EOF 2023/koh-jeopardy/onelinecrypto>)             | Crypto   | RSA, LSB              | ★          |
| [NotLFSR](<AIS3 EOF 2023/koh-jeopardy/NotLFSR>)                         | Crypto   | LFSR                  | ★☆         |
| [magicRSA](<AIS3 EOF 2023/koh-jeopardy/magicRSA>)                       | Crypto   | RSA                   | ★☆         |
| [Neo RSA](<AIS3 EOF 2023/koh-jeopardy/neo_rsa>)                         | Crypto   | RSA, coppersmith      | ★★         |

## Security BSides Ahmedabad CTF 2022

| Name                                                                      | Category | Tags | Difficulty |
| ------------------------------------------------------------------------- | -------- | ---- | ---------- |
| [A complex number](<Security BSides Ahmedabad CTF 2022/A complex number>) | Crypto   | LLL  | ★★★        |
