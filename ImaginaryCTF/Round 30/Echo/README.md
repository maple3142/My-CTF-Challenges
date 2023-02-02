# Echo

* Round: 30 (2023/01)
* Category: Web
* Points: 125
* Solves: 12

## Description

An echo service that employs microservices architecture!

## Solution

`Content-Length` is the message length in `str`, but it should be `bytes`, so we can smuggle an extra request using Unicode characters. To force it to be handled correctly in gunicorn you need to align the request to `chunk_size`.

[solve.py](solve.py)

But it turns out you don't need to align the second request to `chunk_size` as other people who solved this challenge told me. After some testing, it turns how it is gunicorn's worker type affecting this:

When I use `gunicorn -k gevent --keep-alive 1 --bind 0.0.0.0:7777 api:app` then there is no need to align anything, but if you are using `gunicorn -k gthread -t 2 --keep-alive 1 --bind 0.0.0.0:7777 api:app` then you must align it as it probably does what Chromium does.
