# Login System

* Category: Web
* Score: ?/500
* Solves: ?

## Description

A simple website where you can register, login and view your profile.

## Overview

There is a login system implemented in Nim, and a front-end service written in Node.js express. You need to find a way to get RCE.

## Solution

### TL;DR

* There is a request smuggling in Nim `std/asynchttpserver` that allows you to `POST /change_password`.
* Nim `std/json` will parser large number as unquoted string, which will lead to JSON injection when modified.
* JSON injection can be used to change your `privilegeLevel`, and `privilegeLevel` can be used to path traversal load arbitrary yaml on the node.js server.
* Nim is still vulnerable to null truncation, so you can combine it with the JSON injection create a malicious yaml in the container.
* `js-yaml` version is `3.14.1`, which is the last version that default to a dangerous schema that allows you to construct arbitrary JS function with `!!js/function` tag.
* `toString` will be called when something is converted to string, and EJS does that when `res.locals.privilegeLevel` is used in template.

For more details please see my solver [solve.py](./solve.py). I will try to explain some details in the following sections.

### `std/asynchttpserver` Request Smuggling

In Nim's HTTP handling, it will try to check `Transfer-Encoding` is equal to `chunked` or not [here](https://github.com/nim-lang/Nim/blob/v1.6.14/lib/pure/asynchttpserver.nim#L158-L167), but it doesn't consider the case that `chunked` could be uppercased like `CHUNKED`. But in Node.js, `Transfer-Encoding: CHUNKED` is okay, and Node.js will handle it correctly, so this is a TE.TE request smuggling.

So how to smuggle a request that Nim will accept?

Nim's HTTP handling starts [here](https://github.com/nim-lang/Nim/blob/v1.6.14/lib/pure/asynchttpserver.nim#L352-L367), and the most important part is:

```nim
while not client.isClosed:
    let retry = await processRequest(
        server, request, client, address, lineFut, callback
    )
    if not retry:
        client.close()
        break
```

And in the [`processRequest`](https://github.com/nim-lang/Nim/blob/v1.6.14/lib/pure/asynchttpserver.nim#L169) function, [it](https://github.com/nim-lang/Nim/blob/v1.6.14/lib/pure/asynchttpserver.nim#L209-L241) will simply return true if request line doesn't look like a HTTP request.

More simply, `std/asynchttpserver` parsing logic is roughly like this:

```python
while True:
    line = readline(request)
    if not lookslikehttprequest(line):
        continue
    process(request)
```

So all you need is to put your smuggled http request in the body of the first request. You won't get response for this, but you don't need it either.

### `std/json`'s behavior on large numbers

The weird behavior can be demonstrated by this code:

```nim
import std/json

let jsonNode = parseJson("""{"a": 123, "b": "hello", "c": 22222222222222222222222}""")

for key in keys(jsonNode):
    if jsonNode[key].kind == JString:
        echo key, " ", jsonNode[key].str
        jsonNode[key].str = "abcd"
echo $jsonNode
```

The output is:

```
b hello
c 22222222222222222222222
{"a":123,"b":"abcd","c":abcd}
```

Apparently, the large number `22222222222222222222222` is parsed as a string, and when you modify it, it result in a malformed JSON somehow.

This happens because `std/json` will try to [parse a number](https://github.com/nim-lang/Nim/blob/v1.6.14/lib/pure/json.nim#L325-L330) as `RawNumber` if it can't be represented as integer sizes supported by Nim. And the [`RawNumber`](https://github.com/nim-lang/Nim/blob/v1.6.14/lib/pure/json.nim#L211-L216) is actually a string with `isUnquoted: true`. The direct consequence is that the [string won't be quoted](https://github.com/nim-lang/Nim/blob/v1.6.14/lib/pure/json.nim#L725-L729) when it is converted back to JSON.

### Chaining all these together

You will need to use the json injection bug twice. The first one would be a malicious YAML with `privilegeLevel` being `{ toString: !!js/function "..." }`. Since Node.js part require the file to have `.yaml` extension, you need to set username to `???.yaml\x00` cause Nim to null truncate the saved filename to `???.yaml`.

The second one would be a JSON with `privilegeLevel` being a path traversal payload to the YAML you get from above (`../../../users/...`). Once you login with the second user, the code execution will be triggered when you visit `/profile` as EJS triggers `toString`.

## Appendix: Instancer Fix

This is not related to solving the challenge, but there is a mistake in [./spawner/Dockerfile](./dist/spawner/Dockerfile) that needs to be fixed for running the instancer.

```diff
--- spawner/Dockerfile  2023-09-09 23:55:37.376919309 +0800
+++ spawner/Dockerfile.new      2023-09-09 23:55:52.976914563 +0800
@@ -5,8 +5,8 @@
 COPY ./image /image
 RUN mkdir /www
 COPY ./www/package.json ./www/yarn.lock /www
+WORKDIR /www
 RUN yarn
 COPY ./www /www
-WORKDIR /www

 ENTRYPOINT ["/www/run.sh"]
```

That said, if all you need is to run the challenge locally, just `cd web; docker-compose up -d` and you are good to go.
