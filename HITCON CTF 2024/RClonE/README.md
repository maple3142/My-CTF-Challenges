# RClonE

* Category: Web
* Score: 262/500
* Solves: 27

## Description

Rclone is a CLI that syncs your files to various cloud storage. But do you know it also have a built-in web UI?

## Overview

The service runs a [rclone rcd](https://rclone.org/commands/rclone_rcd/) service in an internal network without network access, and provides an Admin Bot the is already authenticated to the rlcone rcd. The target is to execute `/readflag` in the rclone container using the Admin Bot.

## Solution

Note that rclone rcd is authenticated using HTTP Basic Auth, so you can use CSRF to make `GET` or `POST` request to the rclone service, and try to gain RCE from it.

We can use `POST /config/create` to create any rclone remote, and one of them is [SFTP](https://rclone.org/sftp/), which supports [specifying a ssh command](https://rclone.org/sftp/#sftp-ssh) to execute.

So all you need is to:

1. Create a new SFTP remote with desired command to execute in the `ssh` field.
2. Trigger any file operations (e.g. list) on it and it will run the command.

The only problem is that the rclone container does not have internet access, so you have to exfiltrate the flag by sending a url to the Admin Bot.

See [solve.html](./solution/solve.html) for my exploit.
