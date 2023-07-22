# Encrypted Command Executor

* Round: 35 (2023/06)
* Category: Crypto
* Points: 100
* Solves: 28

## Description

A service that only executes encrypted commands. Regular users can only run `echo` or `ls` commands. The command execution output is encrypted too btw.

The server do not allow any outbound network connection, and the flag is located at `/flag`.

## Solution

Use ECB cut and paste to get arbitrary command execution, and leak the flag char by char by comparing it with a precomputed table of `encrypt(key, PADDING + char)`.

Alternative solution: Since `echo` command echoes the input as is, we can use that to generate desired commands. No needs to cut and paste. Timing attack is also possible too.
